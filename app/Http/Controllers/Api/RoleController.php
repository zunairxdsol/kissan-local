<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Role;
use App\Models\Permission;
use App\Models\ActivityLog;
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

            // Search by name
            if ($request->has('search')) {
                $query->where('name', 'like', '%' . $request->search . '%');
            }

            // Pagination
            $perPage = $request->get('per_page', 15);
            $roles = $query->orderBy('name')->paginate($perPage);

            // Add users count to each role
            $roles->getCollection()->transform(function ($role) {
                $role->users_count = $role->users()->count();
                return $role;
            });

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'roles_list',
                'table_name' => 'roles',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $roles,
                'message' => 'Roles retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
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
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $role = Role::create([
                'name' => $request->name,
                'description' => $request->description,
                'permissions' => $request->permissions ?? [],
                'is_active' => $request->is_active ?? true,
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

            return response()->json([
                'success' => true,
                'message' => 'Role created successfully',
                'data' => $role
            ], 201);

        } catch (\Exception $e) {
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
            $role = Role::findOrFail($id);
            $role->users_count = $role->users()->count();

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
            'name' => 'required|string|max:255|unique:roles,name,' . $id,
            'description' => 'nullable|string|max:1000',
            'permissions' => 'nullable|array',
            'permissions.*' => 'string|exists:permissions,name',
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
            $role = Role::findOrFail($id);
            $oldData = $role->toArray();

            $role->update([
                'name' => $request->name,
                'description' => $request->description,
                'permissions' => $request->permissions ?? [],
                'is_active' => $request->is_active ?? $role->is_active,
            ]);

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
                ],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Role updated successfully',
                'data' => $role
            ], 200);

        } catch (\Exception $e) {
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

            // Check if role has users
            if ($role->users()->count() > 0) {
                return response()->json([
                    'success' => false,
                    'message' => 'Cannot delete role with assigned users'
                ], 400);
            }

            $oldData = $role->toArray();
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
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $role = Role::findOrFail($id);
            $oldPermissions = $role->permissions;

            $role->syncPermissions($request->permissions);

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
                ],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Permissions assigned successfully',
                'data' => $role
            ], 200);

        } catch (\Exception $e) {
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
            $permissions = Permission::groupedByModule();

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
}