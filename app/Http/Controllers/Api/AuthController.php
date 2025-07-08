<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Role;
use App\Models\ActivityLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role_id' => 'nullable',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            // Create user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role_id' => $request->role_id ?? $this->getDefaultRoleId(),
                'status' => 'active',
            ]);

            // Load user with role
            $user->load('role');

            // Log the registration activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'register',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => [
                    'name' => $request->name,
                    'email' => $request->email,
                    'role_id' => $request->role_id,
                ],
                'response_status' => 201,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'User registered successfully',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role ? [
                            'id' => $user->role->id,
                            'name' => $user->role->name,
                            'permissions' => $user->role->permissions,
                        ] : null,
                        'status' => $user->status,
                        'created_at' => $user->created_at,
                    ]
                ]
            ], 201);

        } catch (\Exception $e) {
            // Log the error
            ActivityLog::createLog([
                'action' => 'register_failed',
                'request_data' => [
                    'name' => $request->name,
                    'email' => $request->email,
                ],
                'response_status' => 500,
                'response_data' => ['error' => $e->getMessage()],
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Registration failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                // Log failed login attempt
                ActivityLog::createLog([
                    'action' => 'login_failed',
                    'request_data' => [
                        'email' => $request->email,
                    ],
                    'response_status' => 401,
                    'response_data' => ['error' => 'Invalid credentials'],
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Invalid credentials'
                ], 401);
            }

            if ($user->status !== 'active') {
                ActivityLog::createLog([
                    'user_id' => $user->id,
                    'action' => 'login_failed',
                    'request_data' => [
                        'email' => $request->email,
                    ],
                    'response_status' => 403,
                    'response_data' => ['error' => 'Account is not active'],
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Account is not active'
                ], 403);
            }

            // Generate custom token
            $token = Str::random(80);
            $expiresAt = now()->addDays(30); // Token expires in 30 days

            // Update user's last login
            $user->update(['last_login_at' => now()]);

            // Load user with role
            $user->load('role');

            // Log successful login and save token
            ActivityLog::logLogin($user, $token, $expiresAt);

            return response()->json([
                'success' => true,
                'message' => 'Login successful',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role ? [
                            'id' => $user->role->id,
                            'name' => $user->role->name,
                            'permissions' => $user->role->permissions,
                        ] : null,
                        'status' => $user->status,
                        'last_login_at' => $user->last_login_at,
                    ],
                    'token' => $token,
                    'expires_at' => $expiresAt,
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log the error
            ActivityLog::createLog([
                'action' => 'login_error',
                'request_data' => [
                    'email' => $request->email,
                ],
                'response_status' => 500,
                'response_data' => ['error' => $e->getMessage()],
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Login failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $token = $request->bearerToken();
            $user = $request->user();

            if ($token && $user) {
                // Log logout activity
                ActivityLog::logLogout($user, $token);

                // Invalidate the token
                ActivityLog::invalidateToken($token);

                return response()->json([
                    'success' => true,
                    'message' => 'Logout successful'
                ], 200);
            }

            return response()->json([
                'success' => false,
                'message' => 'No active session found'
            ], 401);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Logout failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function me(Request $request)
    {
        try {
            $user = $request->user();
            $user->load('role');

            return response()->json([
                'success' => true,
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role ? [
                            'id' => $user->role->id,
                            'name' => $user->role->name,
                            'permissions' => $user->role->permissions,
                        ] : null,
                        'status' => $user->status,
                        'last_login_at' => $user->last_login_at,
                        'created_at' => $user->created_at,
                        'updated_at' => $user->updated_at,
                    ]
                ]
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to get user data',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function refreshToken(Request $request)
    {
        try {
            $currentToken = $request->bearerToken();
            $user = $request->user();

            if (!$currentToken || !$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid token'
                ], 401);
            }

            // Generate new token
            $newToken = Str::random(80);
            $expiresAt = now()->addDays(30);

            // Invalidate old token
            ActivityLog::invalidateToken($currentToken);

            // Log new token
            ActivityLog::logLogin($user, $newToken, $expiresAt);

            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'data' => [
                    'token' => $newToken,
                    'expires_at' => $expiresAt,
                ]
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token refresh failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    private function getDefaultRoleId()
    {
        // Get default role (e.g., 'user' role)
        $defaultRole = Role::where('name', 'user')->first();
        return $defaultRole ? $defaultRole->id : null;
    }
}