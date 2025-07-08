<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Permission;
use App\Models\ActivityLog;
use App\Models\AuditLog;
use App\Models\ErrorLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PermissionController extends Controller
{
    public function index(Request $request)
    {
        try {
            $query = Permission::query();

            // Filter by module
            if ($request->has('module')) {
                $query->where('module', $request->module);
            }

            // Filter by status
            if ($request->has('status')) {
                $query->where('is_active', $request->status === 'active');
            }

            // Search by name or description
            if ($request->has('search')) {
                $search = $request->search;
                $query->where(function($q) use ($search) {
                    $q->where('name', 'like', '%' . $search . '%')
                      ->orWhere('description', 'like', '%' . $search . '%');
                });
            }

            // Get grouped or flat list
            if ($request->has('grouped') && $request->grouped) {
                $permissions = Permission::groupedByModule();
            } else {
                $perPage = $request->get('per_page', 15);
                $permissions = $query->orderBy('module')->orderBy('action')->paginate($perPage);
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_list',
                'table_name' => 'permissions',
                'request_data' => $request->only(['module', 'status', 'search', 'grouped', 'per_page']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $permissions,
                'message' => 'Permissions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'permissions_list',
                'filters' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|unique:permissions',
            'description' => 'nullable|string|max:1000',
            'module' => 'required|string|max:100',
            'action' => 'required|string|max:100',
            'is_active' => 'boolean',
            'priority' => 'nullable|integer|min:1|max:100',
            'dependencies' => 'nullable|array',
            'dependencies.*' => 'string|exists:permissions,name',
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
            // Check for duplicate name patterns
            $similarPermissions = Permission::where('name', 'like', '%' . $request->name . '%')
                ->orWhere(function($query) use ($request) {
                    $query->where('module', $request->module)
                          ->where('action', $request->action);
                })
                ->get();

            if ($similarPermissions->isNotEmpty()) {
                ErrorLog::logApiError('Similar permission already exists', 409, $request->user()->id, [
                    'requested_permission' => $request->name,
                    'similar_permissions' => $similarPermissions->pluck('name')
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Similar permission already exists',
                    'similar_permissions' => $similarPermissions->pluck('name')
                ], 409);
            }

            $permission = Permission::create([
                'name' => $request->name,
                'description' => $request->description,
                'module' => $request->module,
                'action' => $request->action,
                'is_active' => $request->is_active ?? true,
                'priority' => $request->priority ?? 50,
                'dependencies' => $request->dependencies ?? [],
            ]);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_created',
                'table_name' => 'permissions',
                'record_id' => $permission->id,
                'request_data' => $request->all(),
                'response_status' => 201,
            ]);

            // Log audit
            AuditLog::logCreate($permission, $request->user()->id, 'Permission created via API');

            return response()->json([
                'success' => true,
                'message' => 'Permission created successfully',
                'data' => $permission
            ], 201);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'permission_create',
                'permission_data' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create permission',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function show(Request $request, $id)
    {
        try {
            $permission = Permission::findOrFail($id);

            // Get permission usage statistics
            $usageStats = [
                'roles_using' => \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count(),
                'created_by' => $permission->created_by ?? 'System',
                'last_modified' => $permission->updated_at,
            ];

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_viewed',
                'table_name' => 'permissions',
                'record_id' => $permission->id,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'permission' => $permission,
                    'usage_stats' => $usageStats
                ],
                'message' => 'Permission retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'permission_show',
                'permission_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Permission not found',
                'error' => $e->getMessage()
            ], 404);
        }
    }

    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255|unique:permissions,name,' . $id,
            'description' => 'sometimes|nullable|string|max:1000',
            'module' => 'sometimes|string|max:100',
            'action' => 'sometimes|string|max:100',
            'is_active' => 'sometimes|boolean',
            'priority' => 'sometimes|integer|min:1|max:100',
            'dependencies' => 'sometimes|array',
            'dependencies.*' => 'string|exists:permissions,name',
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
            $permission = Permission::findOrFail($id);
            $oldData = $permission->toArray();

            // Check if permission is being used and if critical changes are being made
            $rolesUsingPermission = \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count();
            
            if ($rolesUsingPermission > 0 && $request->has('name') && $request->name !== $permission->name) {
                ErrorLog::logApiError('Attempted to change name of permission in use', 409, $request->user()->id, [
                    'permission_id' => $id,
                    'current_name' => $permission->name,
                    'new_name' => $request->name,
                    'roles_affected' => $rolesUsingPermission
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot change permission name as it is assigned to ' . $rolesUsingPermission . ' role(s)',
                    'roles_count' => $rolesUsingPermission
                ], 409);
            }

            $updateData = [];

            if ($request->has('name')) {
                $updateData['name'] = $request->name;
            }
            if ($request->has('description')) {
                $updateData['description'] = $request->description;
            }
            if ($request->has('module')) {
                $updateData['module'] = $request->module;
            }
            if ($request->has('action')) {
                $updateData['action'] = $request->action;
            }
            if ($request->has('is_active')) {
                $updateData['is_active'] = $request->is_active;
            }
            if ($request->has('priority')) {
                $updateData['priority'] = $request->priority;
            }
            if ($request->has('dependencies')) {
                $updateData['dependencies'] = $request->dependencies;
            }

            $permission->update($updateData);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_updated',
                'table_name' => 'permissions',
                'record_id' => $permission->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'old_data' => $oldData,
                    'new_data' => $permission->toArray(),
                    'roles_affected' => $rolesUsingPermission,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($permission, $oldData, $request->user()->id, 'Permission updated via API');

            return response()->json([
                'success' => true,
                'message' => 'Permission updated successfully',
                'data' => $permission
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'permission_update',
                'permission_id' => $id,
                'update_data' => $request->all()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update permission',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function destroy(Request $request, $id)
    {
        try {
            $permission = Permission::findOrFail($id);
            
            // Check if permission is being used by any roles
            $rolesUsingPermission = \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count();
            
            if ($rolesUsingPermission > 0) {
                ErrorLog::logApiError('Attempted to delete permission in use', 409, $request->user()->id, [
                    'permission_id' => $id,
                    'permission_name' => $permission->name,
                    'roles_affected' => $rolesUsingPermission
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete permission as it is assigned to one or more roles',
                    'roles_count' => $rolesUsingPermission
                ], 400);
            }

            $oldData = $permission->toArray();

            // Log audit before deletion
            AuditLog::logDelete($permission, $request->user()->id, 'Permission deleted via API');

            $permission->delete();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_deleted',
                'table_name' => 'permissions',
                'record_id' => $id,
                'response_data' => ['deleted_data' => $oldData],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Permission deleted successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'permission_delete',
                'permission_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to delete permission',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getModules(Request $request)
    {
        try {
            $modules = Permission::active()
                ->select('module')
                ->distinct()
                ->orderBy('module')
                ->pluck('module');

            // Add module statistics
            $moduleStats = Permission::selectRaw('module, COUNT(*) as count, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_count')
                ->groupBy('module')
                ->orderBy('module')
                ->get();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'modules_list',
                'table_name' => 'permissions',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'modules' => $modules,
                    'module_statistics' => $moduleStats
                ],
                'message' => 'Modules retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_modules'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve modules',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getActions(Request $request)
    {
        try {
            $query = Permission::active()->select('action')->distinct();

            // Filter by module if provided
            if ($request->has('module')) {
                $query->where('module', $request->module);
            }

            $actions = $query->orderBy('action')->pluck('action');

            // Add action statistics
            $actionStats = Permission::selectRaw('action, COUNT(*) as count, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_count')
                ->when($request->has('module'), function($q) use ($request) {
                    return $q->where('module', $request->module);
                })
                ->groupBy('action')
                ->orderBy('action')
                ->get();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'actions_list',
                'table_name' => 'permissions',
                'request_data' => $request->only(['module']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'actions' => $actions,
                    'action_statistics' => $actionStats
                ],
                'message' => 'Actions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_actions',
                'module' => $request->module
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve actions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function bulkCreate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'permissions' => 'required|array|min:1|max:100', // Limit bulk operations
            'permissions.*.name' => 'required|string|max:255|unique:permissions,name',
            'permissions.*.description' => 'nullable|string|max:1000',
            'permissions.*.module' => 'required|string|max:100',
            'permissions.*.action' => 'required|string|max:100',
            'permissions.*.is_active' => 'boolean',
            'permissions.*.priority' => 'nullable|integer|min:1|max:100',
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
            $permissions = [];
            $createdCount = 0;
            $errors = [];

            foreach ($request->permissions as $index => $permissionData) {
                try {
                    $permission = Permission::create([
                        'name' => $permissionData['name'],
                        'description' => $permissionData['description'] ?? null,
                        'module' => $permissionData['module'],
                        'action' => $permissionData['action'],
                        'is_active' => $permissionData['is_active'] ?? true,
                        'priority' => $permissionData['priority'] ?? 50,
                    ]);
                    
                    // Log audit for each created permission
                    AuditLog::logCreate($permission, $request->user()->id, 'Permission created via bulk API');
                    
                    $permissions[] = $permission;
                    $createdCount++;
                    
                } catch (\Exception $e) {
                    ErrorLog::logException($e, $request->user()->id, [
                        'bulk_create_index' => $index,
                        'permission_data' => $permissionData
                    ]);

                    $errors[] = [
                        'index' => $index,
                        'permission' => $permissionData['name'],
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_bulk_created',
                'table_name' => 'permissions',
                'request_data' => [
                    'total_requested' => count($request->permissions),
                    'created_count' => $createdCount,
                    'errors_count' => count($errors)
                ],
                'response_data' => [
                    'created_count' => $createdCount,
                    'errors_count' => count($errors),
                    'errors' => $errors
                ],
                'response_status' => $createdCount > 0 ? 201 : 400,
            ]);

            if ($createdCount === 0) {
                return response()->json([
                    'success' => false,
                    'message' => 'No permissions were created',
                    'errors' => $errors
                ], 400);
            }

            return response()->json([
                'success' => true,
                'message' => $createdCount . ' permissions created successfully',
                'data' => [
                    'created_permissions' => $permissions,
                    'created_count' => $createdCount,
                    'errors' => $errors
                ]
            ], 201);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'bulk_create_permissions'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to create permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function bulkUpdate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'permissions' => 'required|array|min:1|max:100',
            'permissions.*.id' => 'required|exists:permissions,id',
            'permissions.*.name' => 'required|string|max:255',
            'permissions.*.description' => 'nullable|string|max:1000',
            'permissions.*.module' => 'required|string|max:100',
            'permissions.*.action' => 'required|string|max:100',
            'permissions.*.is_active' => 'boolean',
            'permissions.*.priority' => 'nullable|integer|min:1|max:100',
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
            $updatedPermissions = [];
            $updatedCount = 0;
            $errors = [];

            foreach ($request->permissions as $index => $permissionData) {
                try {
                    $permission = Permission::findOrFail($permissionData['id']);
                    
                    // Check if name is unique (excluding current permission)
                    $existingPermission = Permission::where('name', $permissionData['name'])
                        ->where('id', '!=', $permission->id)
                        ->first();
                    
                    if ($existingPermission) {
                        $errors[] = [
                            'index' => $index,
                            'permission_id' => $permissionData['id'],
                            'error' => 'Permission name already exists'
                        ];
                        continue;
                    }

                    $oldData = $permission->toArray();

                    $permission->update([
                        'name' => $permissionData['name'],
                        'description' => $permissionData['description'] ?? null,
                        'module' => $permissionData['module'],
                        'action' => $permissionData['action'],
                        'is_active' => $permissionData['is_active'] ?? $permission->is_active,
                        'priority' => $permissionData['priority'] ?? $permission->priority,
                    ]);
                    
                    // Log audit for each updated permission
                    AuditLog::logUpdate($permission, $oldData, $request->user()->id, 'Permission updated via bulk API');
                    
                    $updatedPermissions[] = [
                        'permission' => $permission,
                        'old_data' => $oldData
                    ];
                    $updatedCount++;
                    
                } catch (\Exception $e) {
                    ErrorLog::logException($e, $request->user()->id, [
                        'bulk_update_index' => $index,
                        'permission_data' => $permissionData
                    ]);

                    $errors[] = [
                        'index' => $index,
                        'permission_id' => $permissionData['id'] ?? null,
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_bulk_updated',
                'table_name' => 'permissions',
                'request_data' => [
                    'total_requested' => count($request->permissions),
                    'updated_count' => $updatedCount,
                    'errors_count' => count($errors)
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
                    'message' => 'No permissions were updated',
                    'errors' => $errors
                ], 400);
            }

            return response()->json([
                'success' => true,
                'message' => $updatedCount . ' permissions updated successfully',
                'data' => [
                    'updated_permissions' => array_column($updatedPermissions, 'permission'),
                    'updated_count' => $updatedCount,
                    'errors' => $errors
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'bulk_update_permissions'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function bulkDelete(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'permission_ids' => 'required|array|min:1|max:100',
            'permission_ids.*' => 'required|exists:permissions,id',
            'force_delete' => 'nullable|boolean',
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
            $deletedPermissions = [];
            $deletedCount = 0;
            $errors = [];
            $forceDelete = $request->get('force_delete', false);

            foreach ($request->permission_ids as $permissionId) {
                try {
                    $permission = Permission::findOrFail($permissionId);
                    
                    // Check if permission is being used by any roles
                    $rolesUsingPermission = \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count();
                    
                    if ($rolesUsingPermission > 0 && !$forceDelete) {
                        $errors[] = [
                            'permission_id' => $permissionId,
                            'permission_name' => $permission->name,
                            'error' => 'Permission is assigned to ' . $rolesUsingPermission . ' role(s)'
                        ];
                        continue;
                    }

                    $deletedData = $permission->toArray();
                    
                    // Log audit before deletion
                    AuditLog::logDelete($permission, $request->user()->id, $request->reason ?? 'Permission deleted via bulk API');
                    
                    $permission->delete();
                    
                    $deletedPermissions[] = $deletedData;
                    $deletedCount++;
                    
                } catch (\Exception $e) {
                    ErrorLog::logException($e, $request->user()->id, [
                        'bulk_delete_permission_id' => $permissionId
                    ]);

                    $errors[] = [
                        'permission_id' => $permissionId,
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_bulk_deleted',
                'table_name' => 'permissions',
                'request_data' => [
                    'total_requested' => count($request->permission_ids),
                    'deleted_count' => $deletedCount,
                    'errors_count' => count($errors),
                    'force_delete' => $forceDelete,
                    'reason' => $request->reason
                ],
                'response_data' => [
                    'deleted_count' => $deletedCount,
                    'errors_count' => count($errors),
                    'deleted_permissions' => $deletedPermissions,
                    'errors' => $errors
                ],
                'response_status' => $deletedCount > 0 ? 200 : 400,
            ]);

            if ($deletedCount === 0) {
                return response()->json([
                    'success' => false,
                    'message' => 'No permissions were deleted',
                    'errors' => $errors
                ], 400);
            }

            return response()->json([
                'success' => true,
                'message' => $deletedCount . ' permissions deleted successfully',
                'data' => [
                    'deleted_count' => $deletedCount,
                    'errors' => $errors
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'bulk_delete_permissions'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to delete permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function toggleStatus(Request $request, $id)
    {
        try {
            $permission = Permission::findOrFail($id);
            $oldData = $permission->toArray();
            $oldStatus = $permission->is_active;
            $newStatus = !$oldStatus;

            $permission->update(['is_active' => $newStatus]);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_status_toggled',
                'table_name' => 'permissions',
                'record_id' => $permission->id,
                'response_data' => [
                    'old_status' => $oldStatus,
                    'new_status' => $newStatus,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($permission, $oldData, $request->user()->id, 'Permission status toggled via API');

            return response()->json([
                'success' => true,
                'message' => 'Permission status updated successfully',
                'data' => [
                    'permission' => $permission,
                    'old_status' => $oldStatus,
                    'new_status' => $newStatus
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'toggle_permission_status',
                'permission_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to update permission status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function search(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'query' => 'required|string|min:2|max:255',
            'modules' => 'nullable|array',
            'modules.*' => 'string',
            'actions' => 'nullable|array', 
            'actions.*' => 'string',
            'status' => 'nullable|in:active,inactive',
            'priority_min' => 'nullable|integer|min:1',
            'priority_max' => 'nullable|integer|max:100',
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
            $query = Permission::query();

            // Search in name and description
            $searchTerm = $request->query;
            $query->where(function($q) use ($searchTerm) {
                $q->where('name', 'like', '%' . $searchTerm . '%')
                  ->orWhere('description', 'like', '%' . $searchTerm . '%')
                  ->orWhere('module', 'like', '%' . $searchTerm . '%')
                  ->orWhere('action', 'like', '%' . $searchTerm . '%');
            });

            // Filter by modules
            if ($request->has('modules') && !empty($request->modules)) {
                $query->whereIn('module', $request->modules);
            }

            // Filter by actions
            if ($request->has('actions') && !empty($request->actions)) {
                $query->whereIn('action', $request->actions);
            }

            // Filter by status
            if ($request->has('status')) {
                $query->where('is_active', $request->status === 'active');
            }

            // Filter by priority range
            if ($request->has('priority_min')) {
                $query->where('priority', '>=', $request->priority_min);
            }

            if ($request->has('priority_max')) {
                $query->where('priority', '<=', $request->priority_max);
            }

            $perPage = $request->get('per_page', 15);
            $permissions = $query->orderBy('module')
                ->orderBy('action')
                ->orderBy('name')
                ->paginate($perPage);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_search',
                'table_name' => 'permissions',
                'request_data' => $request->all(),
                'response_data' => [
                    'results_count' => $permissions->total(),
                    'search_term' => $searchTerm
                ],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $permissions,
                'message' => 'Search completed successfully',
                'search_term' => $searchTerm,
                'filters_applied' => [
                    'modules' => $request->modules ?? [],
                    'actions' => $request->actions ?? [],
                    'status' => $request->status ?? 'all',
                    'priority_range' => [
                        'min' => $request->priority_min,
                        'max' => $request->priority_max
                    ]
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'search_permissions',
                'search_term' => $request->query
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Search failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getStatistics(Request $request)
    {
        try {
            $startDate = $request->get('from_date');
            $endDate = $request->get('to_date');

            $baseQuery = Permission::query();
            
            if ($startDate) {
                $baseQuery->whereDate('created_at', '>=', $startDate);
            }
            
            if ($endDate) {
                $baseQuery->whereDate('created_at', '<=', $endDate);
            }

            $stats = [
                'total_permissions' => $baseQuery->count(),
                'active_permissions' => $baseQuery->where('is_active', true)->count(),
                'inactive_permissions' => $baseQuery->where('is_active', false)->count(),
                'modules_count' => $baseQuery->distinct('module')->count(),
                'actions_count' => $baseQuery->distinct('action')->count(),
                'permissions_by_module' => $baseQuery->selectRaw('module, COUNT(*) as count')
                    ->groupBy('module')
                    ->orderBy('count', 'desc')
                    ->get(),
                'permissions_by_action' => $baseQuery->selectRaw('action, COUNT(*) as count')
                    ->groupBy('action')
                    ->orderBy('count', 'desc')
                    ->get(),
                'permissions_by_priority' => $baseQuery->selectRaw('
                        CASE 
                            WHEN priority >= 80 THEN "High (80-100)"
                            WHEN priority >= 50 THEN "Medium (50-79)"
                            ELSE "Low (1-49)"
                        END as priority_range,
                        COUNT(*) as count
                    ')
                    ->groupBy('priority_range')
                    ->get(),
                'recent_permissions' => $baseQuery->orderBy('created_at', 'desc')
                    ->limit(5)
                    ->get(['id', 'name', 'module', 'action', 'created_at']),
                'usage_statistics' => $this->getPermissionUsageStats(),
            ];

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_statistics',
                'table_name' => 'permissions',
                'request_data' => $request->only(['from_date', 'to_date']),
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $stats,
                'message' => 'Permission statistics retrieved successfully',
                'date_range' => [
                    'from' => $startDate,
                    'to' => $endDate
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_permission_statistics'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve permission statistics',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getPermissionDependencies(Request $request, $id)
    {
        try {
            $permission = Permission::findOrFail($id);
            
            // Get permissions that depend on this one
            $dependents = Permission::where('dependencies', 'LIKE', '%"' . $permission->name . '"%')->get();
            
            // Get permissions this one depends on
            $dependencies = [];
            if ($permission->dependencies) {
                $dependencies = Permission::whereIn('name', $permission->dependencies)->get();
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permission_dependencies_viewed',
                'table_name' => 'permissions',
                'record_id' => $permission->id,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'permission' => $permission,
                    'depends_on' => $dependencies,
                    'dependents' => $dependents,
                    'dependency_tree' => [
                        'depends_on_count' => count($dependencies),
                        'dependents_count' => $dependents->count()
                    ]
                ],
                'message' => 'Permission dependencies retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'get_permission_dependencies',
                'permission_id' => $id
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve permission dependencies',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function syncPermissions(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'source' => 'required|in:database,config,roles',
            'target' => 'required|in:database,config,roles',
            'dry_run' => 'nullable|boolean',
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
            $dryRun = $request->get('dry_run', false);
            $syncResults = [
                'added' => [],
                'updated' => [],
                'removed' => [],
                'conflicts' => []
            ];

            // This is a placeholder for sync logic
            // In a real implementation, you would sync permissions between different sources
            
            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_sync',
                'table_name' => 'permissions',
                'request_data' => $request->all(),
                'response_data' => $syncResults,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $syncResults,
                'message' => $dryRun ? 'Sync simulation completed' : 'Permissions synchronized successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id, [
                'action' => 'sync_permissions'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to sync permissions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    private function getPermissionUsageStats()
    {
        try {
            $permissions = Permission::all();
            $usageStats = [];

            foreach ($permissions as $permission) {
                $rolesCount = \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count();
                $usageStats[] = [
                    'permission_name' => $permission->name,
                    'module' => $permission->module,
                    'roles_count' => $rolesCount,
                    'usage_percentage' => $rolesCount > 0 ? round(($rolesCount / \App\Models\Role::count()) * 100, 2) : 0
                ];
            }

            return collect($usageStats)->sortByDesc('roles_count')->take(10)->values();

        } catch (\Exception $e) {
            ErrorLog::logException($e, auth()->id(), [
                'action' => 'get_permission_usage_stats'
            ]);
            return [];
        }
    }
}