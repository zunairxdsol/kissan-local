<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Role;
use App\Models\ActivityLog;
use App\Models\AuditLog;
use App\Models\ErrorLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function index(Request $request)
    {
        try {
            $query = User::with('role');

            // Filter by status
            if ($request->has('status')) {
                $query->where('status', $request->status);
            }

            // Filter by role
            if ($request->has('role_id')) {
                $query->where('role_id', $request->role_id);
            }

            // Search by name or email
            if ($request->has('search')) {
                $search = $request->search;
                $query->where(function($q) use ($search) {
                    $q->where('name', 'like', '%' . $search . '%')
                      ->orWhere('email', 'like', '%' . $search . '%');
                });
            }

            // Pagination
            $perPage = $request->get('per_page', 15);
            $users = $query->orderBy('created_at', 'desc')->paginate($perPage);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'users_list',
                'table_name' => 'users',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $users,
                'message' => 'Users retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve users',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role_id' => 'nullable',
            'status' => 'nullable|in:active,inactive,suspended',
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
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role_id' => $request->role_id,
                'status' => $request->status ?? 'active',
            ]);

            // Load user with role
            $user->load('role');

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_created',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => [
                    'name' => $request->name,
                    'email' => $request->email,
                    'role_id' => $request->role_id,
                    'status' => $request->status,
                ],
                'response_status' => 201,
            ]);

            // Log audit
            AuditLog::logCreate($user, $request->user()->id, 'User created via API');

            return response()->json([
                'success' => true,
                'message' => 'User created successfully',
                'data' => $user
            ], 201);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to create user',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function show(Request $request, $id)
    {
        try {
            $user = User::with('role')->findOrFail($id);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_viewed',
                'table_name' => 'users',
                'record_id' => $user->id,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => $user,
                'message' => 'User retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'User not found',
                'error' => $e->getMessage()
            ], 404);
        }
    }

    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email|unique:users,email,' . $id,
            'password' => 'sometimes|nullable|string|min:8|confirmed',
            'role_id' => 'sometimes|exists:roles,id',
            'status' => 'sometimes|in:active,inactive,suspended',
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
            $user = User::findOrFail($id);
            $oldData = $user->toArray();
            $updateData = [];

            if ($request->has('name')) {
                $updateData['name'] = $request->name;
            }
            if ($request->has('email')) {
                $updateData['email'] = $request->email;
            }
            if ($request->has('role_id')) {
                $updateData['role_id'] = $request->role_id;
            }
            if ($request->has('status')) {
                $updateData['status'] = $request->status;
            }
            if ($request->filled('password')) {
                $updateData['password'] = Hash::make($request->password);
            }

            $user->update($updateData);
            $user->load('role');

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_updated',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => $request->except(['password', 'password_confirmation']),
                'response_data' => [
                    'old_data' => $oldData,
                    'new_data' => $user->toArray(),
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($user, $oldData, $request->user()->id, 'User updated via API');

            return response()->json([
                'success' => true,
                'message' => 'User updated successfully',
                'data' => $user
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to update user',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function destroy(Request $request, $id)
    {
        try {
            $user = User::findOrFail($id);

            // Prevent user from deleting themselves
            if ($user->id === $request->user()->id) {
                // Log authorization error
                ErrorLog::logAuthorizationError('User attempted to delete their own account', $request->user()->id);
                
                return response()->json([
                    'success' => false,
                    'message' => 'You cannot delete your own account'
                ], 400);
            }

            $oldData = $user->toArray();

            // Log audit before deletion
            AuditLog::logDelete($user, $request->user()->id, 'User deleted via API');

            $user->delete();

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_deleted',
                'table_name' => 'users',
                'record_id' => $id,
                'response_data' => ['deleted_data' => $oldData],
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'User deleted successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to delete user',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function updateProfile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email,' . $request->user()->id,
            'current_password' => 'nullable|string|required_with:password',
            'password' => 'nullable|string|min:8|confirmed',
            'preferences' => 'nullable|array',
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
            $user = $request->user();
            $oldData = $user->toArray();

            // Check current password if new password is provided
            if ($request->filled('password')) {
                if (!Hash::check($request->current_password, $user->password)) {
                    // Log authentication error
                    ErrorLog::logAuthError('Incorrect current password provided during profile update', $user->id);
                    
                    return response()->json([
                        'success' => false,
                        'message' => 'Current password is incorrect'
                    ], 400);
                }
            }

            $updateData = [
                'name' => $request->name,
                'email' => $request->email,
                'preferences' => $request->preferences ?? $user->preferences,
            ];

            if ($request->filled('password')) {
                $updateData['password'] = Hash::make($request->password);
            }

            $user->update($updateData);
            $user->load('role');

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'profile_updated',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => $request->except(['password', 'password_confirmation', 'current_password']),
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($user, $oldData, $user->id, 'Profile updated by user');

            return response()->json([
                'success' => true,
                'message' => 'Profile updated successfully',
                'data' => $user
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to update profile',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function changeStatus(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'status' => 'required|in:active,inactive,suspended',
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
            $user = User::findOrFail($id);
            $oldData = $user->toArray();
            $oldStatus = $user->status;

            $user->update(['status' => $request->status]);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_status_changed',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'old_status' => $oldStatus,
                    'new_status' => $request->status,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($user, $oldData, $request->user()->id, 'User status changed via API');

            return response()->json([
                'success' => true,
                'message' => 'User status updated successfully',
                'data' => $user
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to update user status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function assignRole(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'role_id' => 'required|exists:roles,id',
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
            $user = User::findOrFail($id);
            $oldData = $user->toArray();
            $oldRoleId = $user->role_id;

            $user->update(['role_id' => $request->role_id]);
            $user->load('role');

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_role_assigned',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => $request->all(),
                'response_data' => [
                    'old_role_id' => $oldRoleId,
                    'new_role_id' => $request->role_id,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::logUpdate($user, $oldData, $request->user()->id, 'Role assigned to user via API');

            return response()->json([
                'success' => true,
                'message' => 'Role assigned successfully',
                'data' => $user
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to assign role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Get user's audit history
    public function getUserAuditHistory(Request $request, $id)
    {
        try {
            $user = User::findOrFail($id);
            $auditHistory = AuditLog::getRecordHistory('users', $id);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'user_audit_history_viewed',
                'table_name' => 'users',
                'record_id' => $id,
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'user' => $user,
                    'audit_history' => $auditHistory
                ],
                'message' => 'User audit history retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve user audit history',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Bulk operations with comprehensive logging
    public function bulkUpdate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'users' => 'required|array|min:1',
            'users.*.id' => 'required|exists:users,id',
            'users.*.name' => 'sometimes|string|max:255',
            'users.*.email' => 'sometimes|email',
            'users.*.role_id' => 'sometimes|exists:roles,id',
            'users.*.status' => 'sometimes|in:active,inactive,suspended',
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
            $updatedUsers = [];
            $errors = [];
            $updatedCount = 0;

            foreach ($request->users as $index => $userData) {
                try {
                    $user = User::findOrFail($userData['id']);
                    $oldData = $user->toArray();

                    // Check email uniqueness
                    if (isset($userData['email'])) {
                        $existingUser = User::where('email', $userData['email'])
                            ->where('id', '!=', $user->id)
                            ->first();
                        
                        if ($existingUser) {
                            $errors[] = [
                                'index' => $index,
                                'user_id' => $userData['id'],
                                'error' => 'Email already exists'
                            ];
                            continue;
                        }
                    }

                    $updateData = array_intersect_key($userData, array_flip(['name', 'email', 'role_id', 'status']));
                    $user->update($updateData);
                    $user->load('role');

                    // Log audit for each user
                    AuditLog::logUpdate($user, $oldData, $request->user()->id, 'Bulk update via API');

                    $updatedUsers[] = $user;
                    $updatedCount++;

                } catch (\Exception $e) {
                    ErrorLog::logException($e, $request->user()->id, ['bulk_update_index' => $index]);
                    $errors[] = [
                        'index' => $index,
                        'user_id' => $userData['id'] ?? null,
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $request->user()->id,
                'action' => 'users_bulk_updated',
                'table_name' => 'users',
                'request_data' => $request->all(),
                'response_data' => [
                    'updated_count' => $updatedCount,
                    'errors_count' => count($errors)
                ],
                'response_status' => $updatedCount > 0 ? 200 : 400,
            ]);

            if ($updatedCount === 0) {
                return response()->json([
                    'success' => false,
                    'message' => 'No users were updated',
                    'errors' => $errors
                ], 400);
            }

            return response()->json([
                'success' => true,
                'message' => "{$updatedCount} users updated successfully",
                'data' => [
                    'updated_users' => $updatedUsers,
                    'updated_count' => $updatedCount,
                    'errors' => $errors
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to update users',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}