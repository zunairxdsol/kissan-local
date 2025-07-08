<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Permission;
use App\Models\ActivityLog;
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
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $permissions,
                'message' => 'Permissions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
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
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $permission = Permission::create([
                'name' => $request->name,
                'description' => $request->description,
                'module' => $request->module,
                'action' => $request->action,
                'is_active' => $request->is_active ?? true,
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

            return response()->json([
                'success' => true,
                'message' => 'Permission created successfully',
                'data' => $permission
            ], 201);

        } catch (\Exception $e) {
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
                'data' => $permission,
                'message' => 'Permission retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
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
        'name' => 'sometimes|string|max:255',
        'description' => 'sometimes|nullable|string|max:1000',
        'module' => 'sometimes|string|max:100',
        'action' => 'sometimes|string|max:100',
        'is_active' => 'sometimes|boolean',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'success' => false,
            'message' => 'Validation failed',
            'errors' => $validator->errors()
        ], 422);
    }

    try {
        $permission = Permission::findOrFail($id);
        $oldData = $permission->toArray();

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
            ],
            'response_status' => 200,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Permission updated successfully',
            'data' => $permission
        ], 200);

    } catch (\Exception $e) {
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
                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete permission as it is assigned to one or more roles',
                    'roles_count' => $rolesUsingPermission
                ], 400);
            }

            $oldData = $permission->toArray();
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

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'modules_list',
                'table_name' => 'permissions',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $modules,
                'message' => 'Modules retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
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

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'actions_list',
                'table_name' => 'permissions',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $actions,
                'message' => 'Actions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
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
            'permissions' => 'required|array|min:1',
            'permissions.*.name' => 'required|string|max:255|unique:permissions,name',
            'permissions.*.description' => 'nullable|string|max:1000',
            'permissions.*.module' => 'required|string|max:100',
            'permissions.*.action' => 'required|string|max:100',
            'permissions.*.is_active' => 'boolean',
        ]);

        if ($validator->fails()) {
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
                    ]);
                    
                    $permissions[] = $permission;
                    $createdCount++;
                    
                } catch (\Exception $e) {
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
                'request_data' => $request->all(),
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
            'permissions' => 'required|array|min:1',
            'permissions.*.id' => 'required|exists:permissions,id',
            'permissions.*.name' => 'required|string|max:255',
            'permissions.*.description' => 'nullable|string|max:1000',
            'permissions.*.module' => 'required|string|max:100',
            'permissions.*.action' => 'required|string|max:100',
            'permissions.*.is_active' => 'boolean',
        ]);

        if ($validator->fails()) {
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
                    ]);
                    
                    $updatedPermissions[] = [
                        'permission' => $permission,
                        'old_data' => $oldData
                    ];
                    $updatedCount++;
                    
                } catch (\Exception $e) {
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
                'request_data' => $request->all(),
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
            'permission_ids' => 'required|array|min:1',
            'permission_ids.*' => 'required|exists:permissions,id',
        ]);

        if ($validator->fails()) {
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

            foreach ($request->permission_ids as $permissionId) {
                try {
                    $permission = Permission::findOrFail($permissionId);
                    
                    // Check if permission is being used by any roles
                    $rolesUsingPermission = \App\Models\Role::where('permissions', 'LIKE', '%"' . $permission->name . '"%')->count();
                    
                    if ($rolesUsingPermission > 0) {
                        $errors[] = [
                            'permission_id' => $permissionId,
                            'permission_name' => $permission->name,
                            'error' => 'Permission is assigned to ' . $rolesUsingPermission . ' role(s)'
                        ];
                        continue;
                    }

                    $deletedData = $permission->toArray();
                    $permission->delete();
                    
                    $deletedPermissions[] = $deletedData;
                    $deletedCount++;
                    
                } catch (\Exception $e) {
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
                'request_data' => $request->all(),
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
            'query' => 'required|string|min:2',
            'modules' => 'nullable|array',
            'modules.*' => 'string',
            'actions' => 'nullable|array', 
            'actions.*' => 'string',
            'status' => 'nullable|in:active,inactive',
        ]);

        if ($validator->fails()) {
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
                    'results_count' => $permissions->total()
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
                    'status' => $request->status ?? 'all'
                ]
            ], 200);

        } catch (\Exception $e) {
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
            $stats = [
                'total_permissions' => Permission::count(),
                'active_permissions' => Permission::where('is_active', true)->count(),
                'inactive_permissions' => Permission::where('is_active', false)->count(),
                'modules_count' => Permission::distinct('module')->count(),
                'actions_count' => Permission::distinct('action')->count(),
                'permissions_by_module' => Permission::selectRaw('module, COUNT(*) as count')
                    ->groupBy('module')
                    ->orderBy('count', 'desc')
                    ->get(),
                'permissions_by_action' => Permission::selectRaw('action, COUNT(*) as count')
                    ->groupBy('action')
                    ->orderBy('count', 'desc')
                    ->get(),
                'recent_permissions' => Permission::orderBy('created_at', 'desc')
                    ->limit(5)
                    ->get(['id', 'name', 'module', 'action', 'created_at']),
            ];

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'permissions_statistics',
                'table_name' => 'permissions',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $stats,
                'message' => 'Permission statistics retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve permission statistics',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}