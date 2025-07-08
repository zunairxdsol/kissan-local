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
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role_id' => 'nullable|exists:roles,id',
        ]);

        if ($validator->fails()) {
            // Log validation error
            ErrorLog::logValidationError($validator->errors());
            
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            // Check if role exists if provided
            $roleId = $request->role_id ?? $this->getDefaultRoleId();
            
            if ($roleId && !Role::find($roleId)) {
                ErrorLog::logApiError('Invalid role_id provided during registration', 400, null, [
                    'provided_role_id' => $request->role_id,
                    'email' => $request->email
                ]);
                
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid role specified'
                ], 400);
            }

            // Create user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role_id' => $roleId,
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
                    'role_id' => $roleId,
                ],
                'response_status' => 201,
            ]);

            // Log audit for user creation
            AuditLog::logCreate($user, $user->id, 'User registered via API');

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
            ErrorLog::logException($e, null, [
                'action' => 'register',
                'email' => $request->email,
                'name' => $request->name
            ]);

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
            'remember_me' => 'nullable|boolean',
            'device_name' => 'nullable|string|max:255',
        ]);

        if ($validator->fails()) {
            // Log validation error
            ErrorLog::logValidationError($validator->errors());
            
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
                ErrorLog::logAuthError('Invalid credentials provided', null);
                
                ActivityLog::createLog([
                    'action' => 'login_failed',
                    'request_data' => [
                        'email' => $request->email,
                        'device_name' => $request->device_name,
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
                // Log inactive account login attempt
                ErrorLog::logAuthError('Login attempt on inactive account', $user->id);
                
                ActivityLog::createLog([
                    'user_id' => $user->id,
                    'action' => 'login_failed',
                    'request_data' => [
                        'email' => $request->email,
                        'device_name' => $request->device_name,
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
            $rememberMe = $request->get('remember_me', false);
            $expiresAt = $rememberMe ? now()->addDays(90) : now()->addDays(30);

            // Update user's last login and login count
            $loginData = [
                'last_login_at' => now(),
                'login_count' => ($user->login_count ?? 0) + 1,
            ];

            // Store device info if provided
            if ($request->device_name) {
                $loginData['last_device'] = $request->device_name;
            }

            $user->update($loginData);

            // Load user with role
            $user->load('role');

            // Log successful login and save token
            ActivityLog::logLogin($user, $token, $expiresAt);

            // Log audit for login
            AuditLog::createAudit([
                'user_id' => $user->id,
                'table_name' => 'users',
                'record_id' => $user->id,
                'action' => 'login',
                'new_values' => [
                    'last_login_at' => $user->last_login_at,
                    'login_count' => $user->login_count,
                    'device_name' => $request->device_name,
                    'remember_me' => $rememberMe,
                ],
                'reason' => 'User logged in via API',
            ]);

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
                        'login_count' => $user->login_count,
                    ],
                    'token' => $token,
                    'expires_at' => $expiresAt,
                    'token_type' => 'Bearer',
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log the error
            ErrorLog::logException($e, null, [
                'action' => 'login',
                'email' => $request->email,
                'device_name' => $request->device_name
            ]);

            ActivityLog::createLog([
                'action' => 'login_error',
                'request_data' => [
                    'email' => $request->email,
                    'device_name' => $request->device_name,
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

                // Log audit for logout
                AuditLog::createAudit([
                    'user_id' => $user->id,
                    'table_name' => 'users',
                    'record_id' => $user->id,
                    'action' => 'logout',
                    'old_values' => ['token' => substr($token, 0, 20) . '...'], // Partial token for security
                    'reason' => 'User logged out via API',
                ]);

                // Invalidate the token
                ActivityLog::invalidateToken($token);

                return response()->json([
                    'success' => true,
                    'message' => 'Logout successful'
                ], 200);
            }

            // Log failed logout attempt
            ErrorLog::logAuthError('Logout attempt without valid session', null);

            return response()->json([
                'success' => false,
                'message' => 'No active session found'
            ], 401);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user() ? $request->user()->id : null, [
                'action' => 'logout'
            ]);

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

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'profile_viewed',
                'table_name' => 'users',
                'record_id' => $user->id,
                'response_status' => 200,
            ]);

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
                        'login_count' => $user->login_count ?? 0,
                        'created_at' => $user->created_at,
                        'updated_at' => $user->updated_at,
                    ]
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user() ? $request->user()->id : null, [
                'action' => 'get_profile'
            ]);

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
                ErrorLog::logAuthError('Token refresh attempt with invalid token', $user ? $user->id : null);
                
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid token'
                ], 401);
            }

            // Generate new token
            $newToken = Str::random(80);
            $expiresAt = now()->addDays(30);

            // Log audit for token refresh
            AuditLog::createAudit([
                'user_id' => $user->id,
                'table_name' => 'users',
                'record_id' => $user->id,
                'action' => 'token_refresh',
                'old_values' => ['token' => substr($currentToken, 0, 20) . '...'],
                'new_values' => ['token' => substr($newToken, 0, 20) . '...'],
                'reason' => 'Token refreshed via API',
            ]);

            // Invalidate old token
            ActivityLog::invalidateToken($currentToken);

            // Log new token
            ActivityLog::logLogin($user, $newToken, $expiresAt);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'token_refreshed',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'data' => [
                    'token' => $newToken,
                    'expires_at' => $expiresAt,
                    'token_type' => 'Bearer',
                ]
            ], 200);

        } catch (\Exception $e) {
            // Log error
            ErrorLog::logException($e, $request->user() ? $request->user()->id : null, [
                'action' => 'token_refresh'
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Token refresh failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:8|confirmed',
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
            $user = $request->user();

            // Verify current password
            if (!Hash::check($request->current_password, $user->password)) {
                ErrorLog::logAuthError('Incorrect current password during password change', $user->id);
                
                return response()->json([
                    'success' => false,
                    'message' => 'Current password is incorrect'
                ], 400);
            }

            $oldData = $user->toArray();

            // Update password
            $user->update([
                'password' => Hash::make($request->new_password),
                'password_changed_at' => now(),
            ]);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'password_changed',
                'table_name' => 'users',
                'record_id' => $user->id,
                'response_status' => 200,
            ]);

            // Log audit (without password data for security)
            AuditLog::logUpdate($user, $oldData, $user->id, 'Password changed via API');

            return response()->json([
                'success' => true,
                'message' => 'Password changed successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id, ['action' => 'change_password']);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to change password',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|exists:users,email',
        ]);

        if ($validator->fails()) {
            ErrorLog::logValidationError($validator->errors());
            
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (!$user) {
                // Log attempt on non-existent user
                ErrorLog::logApiError('Password reset attempt on non-existent email', 404, null, [
                    'email' => $request->email
                ]);
                
                return response()->json([
                    'success' => false,
                    'message' => 'User not found'
                ], 404);
            }

            // Generate reset token
            $resetToken = Str::random(60);
            $expiresAt = now()->addHours(1);

            // In a real application, you would store this token in a password_resets table
            // For now, we'll just log the action

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'password_reset_requested',
                'table_name' => 'users',
                'record_id' => $user->id,
                'request_data' => ['email' => $request->email],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::createAudit([
                'user_id' => $user->id,
                'table_name' => 'users',
                'record_id' => $user->id,
                'action' => 'password_reset_requested',
                'new_values' => [
                    'reset_token_generated' => true,
                    'reset_expires_at' => $expiresAt,
                ],
                'reason' => 'Password reset requested via API',
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Password reset instructions sent to your email',
                'data' => [
                    'reset_token' => $resetToken, // In production, send via email
                    'expires_at' => $expiresAt,
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, null, [
                'action' => 'forgot_password',
                'email' => $request->email
            ]);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to process password reset request',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getActiveSessions(Request $request)
    {
        try {
            $user = $request->user();
            $activeSessions = ActivityLog::getUserActiveTokens($user->id);

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'active_sessions_viewed',
                'response_status' => 200,
            ]);

            return response()->json([
                'success' => true,
                'data' => [
                    'active_sessions' => $activeSessions->map(function ($session) {
                        return [
                            'token_preview' => substr($session->auth_token, 0, 20) . '...',
                            'created_at' => $session->created_at,
                            'expires_at' => $session->expires_at,
                            'ip_address' => $session->ip_address,
                            'user_agent' => $session->user_agent,
                        ];
                    }),
                    'total_sessions' => $activeSessions->count(),
                ],
                'message' => 'Active sessions retrieved successfully'
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id, ['action' => 'get_active_sessions']);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve active sessions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function logoutAllSessions(Request $request)
    {
        try {
            $user = $request->user();
            $currentToken = $request->bearerToken();
            
            // Get all active tokens for the user
            $activeSessions = ActivityLog::getUserActiveTokens($user->id);
            
            // Invalidate all tokens except current one if requested
            $keepCurrent = $request->get('keep_current', false);
            $invalidatedCount = 0;

            foreach ($activeSessions as $session) {
                if (!$keepCurrent || $session->auth_token !== $currentToken) {
                    ActivityLog::invalidateToken($session->auth_token);
                    $invalidatedCount++;
                }
            }

            // Log activity
            ActivityLog::createLog([
                'user_id' => $user->id,
                'action' => 'logout_all_sessions',
                'response_data' => [
                    'invalidated_sessions' => $invalidatedCount,
                    'keep_current' => $keepCurrent,
                ],
                'response_status' => 200,
            ]);

            // Log audit
            AuditLog::createAudit([
                'user_id' => $user->id,
                'table_name' => 'users',
                'record_id' => $user->id,
                'action' => 'logout_all_sessions',
                'new_values' => [
                    'invalidated_sessions' => $invalidatedCount,
                    'keep_current_session' => $keepCurrent,
                ],
                'reason' => 'User logged out all sessions via API',
            ]);

            return response()->json([
                'success' => true,
                'message' => "Successfully logged out {$invalidatedCount} sessions",
                'data' => [
                    'invalidated_sessions' => $invalidatedCount,
                    'current_session_preserved' => $keepCurrent,
                ]
            ], 200);

        } catch (\Exception $e) {
            ErrorLog::logException($e, $request->user()->id, ['action' => 'logout_all_sessions']);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to logout all sessions',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    private function getDefaultRoleId()
    {
        try {
            // Get default role (e.g., 'user' role)
            $defaultRole = Role::where('name', 'user')->first();
            return $defaultRole ? $defaultRole->id : null;
        } catch (\Exception $e) {
            ErrorLog::logException($e, null, ['action' => 'get_default_role']);
            return null;
        }
    }
}