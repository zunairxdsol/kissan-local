<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Role;
use App\Models\Permission;
use App\Models\ActivityLog;
use App\Models\AuditLog;
use App\Models\ErrorLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class RoleController extends Controller
{
    public function index(Request $request)
    {
        try {
            $query = Role::query();

            // Filter by status
            if ($request->has('status')) {
                $query->where('is_active', $request->status === 'active');
            }

            // Filter by permission
            if ($request->has('permission')) {
                $query->where('permissions', 'LIKE', '%"' . $request->permission . '"%');
            }

            // Search by name or description
            if ($request->has('search')) {
                $search = $request->search;
                $query->where(function($q) use ($search) {
                    $q->where('name', 'like', '%' . $search . '%')
                      ->orWhere('description', 'like', '%' . $search . '%');
                });
            }

            // Include user counts
            $includeUserCounts = $request->get('include_user_counts', true);

            // Pagination
            $perPage = $request->get('per_page', 15);
            $roles = $query->orderBy('name')->paginate($perPage);

            // Add users count and permission details to each role
            $roles->getCollection()->transform(function ($role) use ($includeUserCounts) {
                if ($includeUserCounts) {
                    $role->users_count = $role->users()->count();
                }
                $role->permissions_count = is_array($role->permissions) ? count($role->permissions) : 0;
                $role->is_system_role = in_array($role->name, ['super_admin', 'admin']);
                return $role;
            });

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'roles_list',
                'table_name' => 'roles',
                'request_data' => $request->only(['status', 'permission', 'search', 'per_page']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $roles,
                'message' => 'Roles retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'roles_list',
                'filters' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve roles',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles',
            'description' => 'nullable|string|max:1000',
            'permissions' => 'nullable|array',
            'permissions.*' => 'string|exists:permissions,name',
            'is_active' => 'boolean',
            'priority' => 'nullable|integer|min:1|max:100',
            'is_system_role' => 'boolean',
            'parent_role_id' => 'nullable|exists:roles,id',
        ]);

        if ($validator->fails()) {
            // Log validation error
            ErrorLog::logValidationError($validator->errors(), $request->user()->id);

            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            // Check for reserved role names
            $reservedNames = ['super_admin', 'admin', 'system', 'root'];
            if (in_array(strtolower($request->name), $reservedNames) && !$request->get('is_system_role', false)) {
                ErrorLog::logApiError('Attempted to create role with reserved name', 409, $request->user()->id, [
                    'requested_name' => $request->name,
                    'reserved_names' => $reservedNames
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Role name is reserved for system use',
                    'reserved_names' => $reservedNames
                ], 409);
            }

            // Validate parent role hierarchy
            if ($request->parent_role_id) {
                $parentRole = Role::find($request->parent_role_id);
                if (!$parentRole || !$parentRole->is_active) {
                    ErrorLog::logApiError('Invalid parent role specified', 400, $request->user()->id, [
                        'parent_role_id' => $request->parent_role_id
                    ]);

                    return response()->json([
                        'success' => false,
                        'message' => 'Invalid or inactive parent role specified'
                    ], 400);
                }
            }

            // Validate permissions exist and are active
            if ($request->permissions) {
                $validPermissions = Permission::whereIn('name', $request->permissions)
                    ->where('is_active', true)
                    ->pluck('name')
                    ->toArray();

                $invalidPermissions = array_diff($request->permissions, $validPermissions);
                if (!empty($invalidPermissions)) {
                    ErrorLog::logApiError('Invalid or inactive permissions specified', 400, $request->user()->id, [
                        'invalid_permissions' => $invalidPermissions
                    ]);

                    return response()->json([
                        'success' => false,
                        'message' => 'Some permissions are invalid or inactive',
                        'invalid_permissions' => $invalidPermissions
                    ], 400);
                }
            }

            $role = Role::create([
                'name' => $request->name,
                'description' => $request->description,
                'permissions' => $request->permissions ?? [],
                'is_active' => $request->is_active ?? true,
                'priority' => $request->priority ?? 50,
                'is_system_role' => $request->is_system_role ?? false,
                'parent_role_id' => $request->parent_role_id,
                'created_by' => $request->user()->id,
            ]);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_created',
                'table_name' => 'roles',
                'record_id' => $role->id,
                'request_data' => $request->all(),
                'response_status' => 201,
            ]);

            // Log audit
            AuditLog::logCreate($role, $request->user()->id, 'Role created via API');

            return response()->json([
                'success' => true,
                'message' => 'Role created successfully',
                'data' => $role
            ], 201);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'role_create',
                'role_data' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function show(Request $request, $id)
    {
        try {
            $role = Role::with(['parent', 'children'])->findOrFail($id);
            
            // Add additional role information
            $role->users_count = $role->users()->count();
            $role->active_users_count = $role->users()->where('status', 'active')->count();
            $role->permissions_count = is_array($role->permissions) ? count($role->permissions) : 0;
            
            // Get permission details
            if ($role->permissions) {
                $role->permission_details = Permission::whereIn('name', $role->permissions)
                    ->get(['name', 'description', 'module', 'action']);
            }

            // Get role hierarchy info
            $role->hierarchy_level = $this->getRoleHierarchyLevel($role);
            $role->inherited_permissions = $this->getInheritedPermissions($role);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_viewed',
                'table_name' => 'roles',
                'record_id' => $role->id,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $role,
                'message' => 'Role retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'role_show',
                'role_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Role not found',
                'error' => $e->getMessage()
            ], 404);
        }
    }

    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255|unique:roles,name,' . $id,
            'description' => 'sometimes|nullable|string|max:1000',
            'permissions' => 'sometimes|array',
            'permissions.*' => 'string|exists:permissions,name',
            'is_active' => 'sometimes|boolean',
            'priority' => 'sometimes|integer|min:1|max:100',
            'parent_role_id' => 'sometimes|nullable|exists:roles,id',
        ]);

        if ($validator->fails()) {
            // Log validation error
            ErrorLog::logValidationError($validator->errors(), $request->user()->id);

            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $role = Role::findOrFail($id);
            $oldData = $role->toArray();

            // Check if role is system role and prevent critical changes
            if ($role->is_system_role && $request->has('name') && $request->name !== $role->name) {
                ErrorLog::logApiError('Attempted to change system role name', 403, $request->user()->id, [
                    'role_id' => $id,
                    'current_name' => $role->name,
                    'new_name' => $request->name
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot change name of system role'
                ], 403);
            }

            // Check for users assigned to role before deactivation
            $usersCount = $role->users()->count();
            if ($request->has('is_active') && !$request->is_active && $usersCount > 0) {
                ErrorLog::logApiError('Attempted to deactivate role with assigned users', 409, $request->user()->id, [
                    'role_id' => $id,
                    'users_count' => $usersCount
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot deactivate role with assigned users',
                    'users_count' => $usersCount
                ], 409);
            }

            // Validate parent role hierarchy to prevent circular references
            if ($request->has('parent_role_id') && $request->parent_role_id) {
                if ($this->wouldCreateCircularReference($id, $request->parent_role_id)) {
                    ErrorLog::logApiError('Circular reference detected in role hierarchy', 409, $request->user()->id, [
                        'role_id' => $id,
                        'parent_role_id' => $request->parent_role_id
                    ]);

                    return response()->json([
                        'success' => false,
                        'message' => 'Cannot set parent role: would create circular reference'
                    ], 409);
                }
            }

            // Validate permissions if provided
            if ($request->has('permissions') && $request->permissions) {
                $validPermissions = Permission::whereIn('name', $request->permissions)
                    ->where('is_active', true)
                    ->pluck('name')
                    ->toArray();

                $invalidPermissions = array_diff($request->permissions, $validPermissions);
                if (!empty($invalidPermissions)) {
                    ErrorLog::logApiError('Invalid permissions in role update', 400, $request->user()->id, [
                        'invalid_permissions' => $invalidPermissions
                    ]);

                    return response()->json([
                        'success' => false,
                        'message' => 'Some permissions are invalid or inactive',
                        'invalid_permissions' => $invalidPermissions
                    ], 400);
                }
            }

            $updateData = [];
            
            if ($request->has('name')) {
                $updateData['name'] = $request->name;
            }
            if ($request->has('description')) {
                $updateData['description'] = $request->description;
            }
            if ($request->has('permissions')) {
                $updateData['permissions'] = $request->permissions;
            }
            if ($request->has('is_active')) {
                $updateData['is_active'] = $request->is_active;
            }
            if ($request->has('priority')) {
                $updateData['priority'] = $request->priority;
            }
            if ($request->has('parent_role_id')) {
                $updateData['parent_role_id'] = $request->parent_role_id;
            }

            $updateData['updated_by'] = $request->user()->id;

            $role->update($updateData);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_updated',
                'table_name' => 'roles',
                'record_id' => $role->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'old_data' => $oldData,
                    'new_data' => $role->toArray(),
                    'users_affected' => $usersCount,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($role, $oldData, $request->user()->id, 'Role updated via API');

            return response()->json([
                'success' => true,
                'message' => 'Role updated successfully',
                'data' => $role
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'role_update',
                'role_id' => $id,
                'update_data' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function destroy(Request $request, $id)
    {
        try {
            $role = Role::findOrFail($id);

            // Check if role is system role
            if ($role->is_system_role) {
                ErrorLog::logApiError('Attempted to delete system role', 403, $request->user()->id, [
                    'role_id' => $id,
                    'role_name' => $role->name
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete system role'
                ], 403);
            }

            // Check if role has users
            $usersCount = $role->users()->count();
            if ($usersCount > 0) {
                ErrorLog::logApiError('Attempted to delete role with assigned users', 409, $request->user()->id, [
                    'role_id' => $id,
                    'users_count' => $usersCount
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete role with assigned users',
                    'users_count' => $usersCount
                ], 409);
            }

            // Check if role has child roles
            $childRolesCount = $role->children()->count();
            if ($childRolesCount > 0) {
                ErrorLog::logApiError('Attempted to delete role with child roles', 409, $request->user()->id, [
                    'role_id' => $id,
                    'child_roles_count' => $childRolesCount
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete role with child roles',
                    'child_roles_count' => $childRolesCount
                ], 409);
            }

            $oldData = $role->toArray();

            // Log audit before deletion
            AuditLog::logDelete($role, $request->user()->id, 'Role deleted via API');

            $role->delete();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_deleted',
                'table_name' => 'roles',
                'record_id' => $id,
                'response_data' => ['deleted_data' => $oldData],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Role deleted successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'role_delete',
                'role_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to delete role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function assignPermissions(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'permissions' => 'required|array',
            'permissions.*' => 'string|exists:permissions,name',
            'mode' => 'nullable|in:replace,add,remove',
            'reason' => 'nullable|string|max:255',
        ]);

        if ($validator->fails()) {
            // Log validation error
            ErrorLog::logValidationError($validator->errors(), $request->user()->id);

            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $role = Role::findOrFail($id);
            $oldPermissions = $role->permissions ?? [];
            $mode = $request->get('mode', 'replace');

            // Validate permissions are active
            $validPermissions = Permission::whereIn('name', $request->permissions)
                ->where('is_active', true)
                ->pluck('name')
                ->toArray();

            $invalidPermissions = array_diff($request->permissions, $validPermissions);
            if (!empty($invalidPermissions)) {
                ErrorLog::logApiError('Invalid permissions in assignment', 400, $request->user()->id, [
                    'invalid_permissions' => $invalidPermissions
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Some permissions are invalid or inactive',
                    'invalid_permissions' => $invalidPermissions
                ], 400);
            }

            $newPermissions = [];

            switch ($mode) {
                case 'add':
                    $newPermissions = array_unique(array_merge($oldPermissions, $request->permissions));
                    break;
                case 'remove':
                    $newPermissions = array_diff($oldPermissions, $request->permissions);
                    break;
                case 'replace':
                default:
                    $newPermissions = $request->permissions;
                    break;
            }

            $role->syncPermissions($newPermissions);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_permissions_updated',
                'table_name' => 'roles',
                'record_id' => $role->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'old_permissions' => $oldPermissions,
                    'new_permissions' => $role->permissions,
                    'mode' => $mode,
                    'reason' => $request->reason,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::createAudit([
                'user_id' => $request->user()->id,
                'table_name' => 'roles',
                'record_id' => $role->id,
                'action' => 'permissions_updated',
                'old_values' => ['permissions' => $oldPermissions],
                'new_values' => ['permissions' => $role->permissions],
                'changed_fields' => ['permissions'],
                'reason' => $request->reason ?? 'Permissions updated via API',
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Permissions assigned successfully',
                'data' => [
                    'role' => $role,
                    'permissions_added' => array_diff($role->permissions, $oldPermissions),
                    'permissions_removed' => array_diff($oldPermissions, $role->permissions),
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'assign_permissions',
                'role_id' => $id,
                'permissions' => $request->permissions
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to assign permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getAllPermissions(Request $request)
    {
        try {
            $groupBy = $request->get('group_by', 'module'); // module, action, priority
            $includeInactive = $request->get('include_inactive', false);

            $query = Permission::query();
            
            if (!$includeInactive) {
                $query->where('is_active', true);
            }

            switch ($groupBy) {
                case 'action':
                    $permissions = $query->get()->groupBy('action');
                    break;
                case 'priority':
                    $permissions = $query->get()->groupBy(function($permission) {
                        if ($permission->priority >= 80) return 'High (80-100)';
                        if ($permission->priority >= 50) return 'Medium (50-79)';
                        return 'Low (1-49)';
                    });
                    break;
                case 'module':
                default:
                    $permissions = Permission::groupedByModule();
                    break;
            }

            // Add permission usage statistics
            $usageStats = $this->getPermissionUsageStatistics();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_list',
                'table_name' => 'permissions',
                'request_data' => $request->only(['group_by', 'include_inactive']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'permissions' => $permissions,
                    'usage_statistics' => $usageStats,
                    'grouped_by' => $groupBy,
                ],
                'message' => 'Permissions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_all_permissions'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getRoleHierarchy(Request $request)
    {
        try {
            $hierarchy = $this->buildRoleHierarchy();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_hierarchy_viewed',
                'table_name' => 'roles',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $hierarchy,
                'message' => 'Role hierarchy retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_role_hierarchy'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve role hierarchy',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getRoleStatistics(Request $request)
    {
        try {
            $startDate = $request->get('from_date');
            $endDate = $request->get('to_date');

            $baseQuery = Role::query();
            
            if ($startDate) {
                $baseQuery->whereDate('created_at', '>=', $startDate);
            }
            
            if ($endDate) {
                $baseQuery->whereDate('created_at', '<=', $endDate);
            }

            $stats = [
                'total_roles' => $baseQuery->count(),
                'active_roles' => $baseQuery->where('is_active', true)->count(),
                'inactive_roles' => $baseQuery->where('is_active', false)->count(),
                'system_roles' => $baseQuery->where('is_system_role', true)->count(),
                'roles_with_users' => Role::has('users')->count(),
                'roles_by_priority' => $baseQuery->selectRaw('
                        CASE 
                            WHEN priority >= 80 THEN "High (80-100)"
                            WHEN priority >= 50 THEN "Medium (50-79)"
                            ELSE "Low (1-49)"
                        END as priority_range,
                        COUNT(*) as count
                    ')
                    ->groupBy('priority_range')
                    ->get(),
                'users_by_role' => Role::withCount('users')
                    ->orderBy('users_count', 'desc')
                    ->limit(10)
                    ->get(['id', 'name', 'users_count']),
                'permissions_distribution' => Role::all()->map(function($role) {
                    return [
                        'role_name' => $role->name,
                        'permissions_count' => is_array($role->permissions) ? count($role->permissions) : 0
                    ];
                })->sortByDesc('permissions_count')->take(10)->values(),
            ];

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_statistics_viewed',
                'table_name' => 'roles',
                'request_data' => $request->only(['from_date', 'to_date']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $stats,
                'message' => 'Role statistics retrieved successfully',
                'date_range' => [
                    'from' => $startDate,
                    'to' => $endDate
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_role_statistics'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve role statistics',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function cloneRole(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:roles',
            'description' => 'nullable|string|max:1000',
            'clone_permissions' => 'nullable|boolean',
            'clone_users' => 'nullable|boolean',
        ]);

        if ($validator->fails()) {
            ErrorLog::logValidationError($validator->errors(), $request->user()->id);

            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $sourceRole = Role::findOrFail($id);
            $clonePermissions = $request->get('clone_permissions', true);
            $cloneUsers = $request->get('clone_users', false);

            $newRole = Role::create([
                'name' => $request->name,
                'description' => $request->description ?? $sourceRole->description . ' (Cloned)',
                'permissions' => $clonePermissions ? $sourceRole->permissions : [],
                'is_active' => true,
                'priority' => $sourceRole->priority,
                'parent_role_id' => $sourceRole->parent_role_id,
                'created_by' => $request->user()->id,
            ]);

            // Clone users if requested
            if ($cloneUsers && $sourceRole->users()->exists()) {
                $userIds = $sourceRole->users()->pluck('id');
                $newRole->users()->attach($userIds);
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'role_cloned',
                'table_name' => 'roles',
                'record_id' => $newRole->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'source_role_id' => $id,
                    'new_role_id' => $newRole->id,
                    'cloned_permissions' => $clonePermissions,
                    'cloned_users' => $cloneUsers,
                ],
                'response_status' => 201,
            ]);

            // Log audit
            AuditLog::logCreate($newRole, $request->user()->id, "Role cloned from {$sourceRole->name}");

            return response()->json([
                'success' => true,
                'message' => 'Role cloned successfully',
                'data' => [
                    'new_role' => $newRole,
                    'source_role' => $sourceRole->only(['id', 'name']),
                    'cloned_users_count' => $cloneUsers ? $sourceRole->users()->count() : 0,
                ]
            ], 201);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'clone_role',
                'source_role_id' => $id,
                'clone_data' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to clone role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function bulkUpdate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'roles' => 'required|array|min:1|max:50',
            'roles.*.id' => 'required|exists:roles,id',
            'roles.*.name' => 'sometimes|string|max:255',
            'roles.*.description' => 'sometimes|nullable|string|max:1000',
            'roles.*.is_active' => 'sometimes|boolean',
            'roles.*.priority' => 'sometimes|integer|min:1|max:100',
            'operation' => 'required|in:update,activate,deactivate',
        ]);

        if ($validator->fails()) {
            ErrorLog::logValidationError($validator->errors(), $request->user()->id);

            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $updatedRoles = [];
            $updatedCount = 0;
            $errors = [];
            $operation = $request->operation;

            foreach ($request->roles as $index => $roleData) {
                try {
                    $role = Role::findOrFail($roleData['id']);
                    
                    // Check if role is system role and prevent critical changes
                    if ($role->is_system_role && isset($roleData['name']) && $roleData['name'] !== $role->name) {
                        $errors[] = [
                            'index' => $index,
                            'role_id' => $roleData['id'],
                            'error' => 'Cannot change name of system role'
                        ];
                        continue;
                    }

                    $oldData = $role->toArray();
                    $updateData = [];

                    switch ($operation) {
                        case 'activate':
                            $updateData['is_active'] = true;
                            break;
                        case 'deactivate':
                            // Check for users before deactivation
                            if ($role->users()->count() > 0) {
                                $errors[] = [
                                    'index' => $index,
                                    'role_id' => $roleData['id'],
                                    'error' => 'Cannot deactivate role with assigned users'
                                ];
                                continue 2;
                            }
                            $updateData['is_active'] = false;
                            break;
                        case 'update':
                            if (isset($roleData['name'])) {
                                // Check name uniqueness
                                $existingRole = Role::where('name', $roleData['name'])
                                    ->where('id', '!=', $role->id)
                                    ->first();
                                
                                if ($existingRole) {
                                    $errors[] = [
                                        'index' => $index,
                                        'role_id' => $roleData['id'],
                                        'error' => 'Role name already exists'
                                    ];
                                    continue 2;
                                }
                                $updateData['name'] = $roleData['name'];
                            }

                            if (isset($roleData['description'])) {
                                $updateData['description'] = $roleData['description'];
                            }

                            if (isset($roleData['is_active'])) {
                                if (!$roleData['is_active'] && $role->users()->count() > 0) {
                                    $errors[] = [
                                        'index' => $index,
                                        'role_id' => $roleData['id'],
                                        'error' => 'Cannot deactivate role with assigned users'
                                    ];
                                    continue 2;
                                }
                                $updateData['is_active'] = $roleData['is_active'];
                            }

                            if (isset($roleData['priority'])) {
                                $updateData['priority'] = $roleData['priority'];
                            }
                            break;
                    }

                    $updateData['updated_by'] = $request->user()->id;
                    $role->update($updateData);

                    // Log audit for each updated role
                    AuditLog::logUpdate($role, $oldData, $request->user()->id, "Role bulk {$operation} via API");

                    $updatedRoles[] = $role;
                    $updatedCount++;

                } catch (\Exception $e) {
                    ErrorLog::logException($e, $request->user()->id, [
                        'bulk_update_index' => $index,
                        'role_data' => $roleData
                    ]);

                    $errors[] = [
                        'index' => $index,
                        'role_id' => $roleData['id'] ?? null,
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'roles_bulk_updated',
                'table_name' => 'roles',
                'request_data' => [
                    'total_requested' => count($request->roles),
                    'updated_count' => $updatedCount,
                    'errors_count' => count($errors),
                    'operation' => $operation
                ],
                'response_data' => [
                    'updated_count' => $updatedCount,
                    'errors_count' => count($errors),
                    'errors' => $errors
                ],
                'response_status' => $updatedCount > 0 ? 200 : 400,
            ]);

            if ($updatedCount === 0) {
                return response()->json([
                    'success' => false,
                    'message' => 'No roles were updated',
                    'errors' => $errors
                ], 400);
            }

            return response()->json([
                'success' => true,
                'message' => "{$updatedCount} roles {$operation}d successfully",
                'data' => [
                    'updated_roles' => $updatedRoles,
                    'updated_count' => $updatedCount,
                    'errors' => $errors
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'bulk_update_roles'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update roles',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Helper methods

    private function getRoleHierarchyLevel($role, $level = 0)
    {
        if (!$role->parent_role_id || $level > 10) { // Prevent infinite recursion
            return $level;
        }

        $parent = Role::find($role->parent_role_id);
        if (!$parent) {
            return $level;
        }

        return $this->getRoleHierarchyLevel($parent, $level + 1);
    }

    private function getInheritedPermissions($role)
    {
        $inheritedPermissions = [];
        $currentRole = $role;

        // Traverse up the hierarchy to collect inherited permissions
        while ($currentRole->parent_role_id) {
            $parent = Role::find($currentRole->parent_role_id);
            if (!$parent) break;

            if ($parent->permissions) {
                $inheritedPermissions = array_merge($inheritedPermissions, $parent->permissions);
            }

            $currentRole = $parent;
        }

        return array_unique($inheritedPermissions);
    }

    private function wouldCreateCircularReference($roleId, $parentRoleId)
    {
        $currentId = $parentRoleId;
        $visited = [];

        while ($currentId && !in_array($currentId, $visited)) {
            if ($currentId == $roleId) {
                return true; // Circular reference detected
            }

            $visited[] = $currentId;
            $parent = Role::find($currentId);
            $currentId = $parent ? $parent->parent_role_id : null;
        }

        return false;
    }

    private function buildRoleHierarchy()
    {
        $roles = Role::all();
        $hierarchy = [];

        // Find root roles (no parent)
        $rootRoles = $roles->whereNull('parent_role_id');

        foreach ($rootRoles as $role) {
            $hierarchy[] = $this->buildRoleTree($role, $roles);
        }

        return $hierarchy;
    }

    private function buildRoleTree($role, $allRoles)
    {
        $roleData = [
            'id' => $role->id,
            'name' => $role->name,
            'description' => $role->description,
            'is_active' => $role->is_active,
            'priority' => $role->priority,
            'users_count' => $role->users()->count(),
            'permissions_count' => is_array($role->permissions) ? count($role->permissions) : 0,
            'children' => []
        ];

        $children = $allRoles->where('parent_role_id', $role->id);
        foreach ($children as $child) {
            $roleData['children'][] = $this->buildRoleTree($child, $allRoles);
        }

        return $roleData;
    }

    private function getPermissionUsageStatistics()
    {
        try {
            $permissions = Permission::all();
            $roles = Role::all();
            $usageStats = [];

            foreach ($permissions as $permission) {
                $rolesUsingPermission = $roles->filter(function($role) use ($permission) {
                    return in_array($permission->name, $role->permissions ?? []);
                });

                $usageStats[] = [
                    'permission_name' => $permission->name,
                    'module' => $permission->module,
                    'roles_count' => $rolesUsingPermission->count(),
                    'usage_percentage' => $roles->count() > 0 ? 
                        round(($rolesUsingPermission->count() / $roles->count()) * 100, 2) : 0
                ];
            }

            return collect($usageStats)->sortByDesc('roles_count')->take(20)->values();

        } catch (\Exception $e) {
            ErrorLog::logException($e, auth()->id(), [
                'action' => 'get_permission_usage_statistics'
            ]);
            return [];
        }
    }
}