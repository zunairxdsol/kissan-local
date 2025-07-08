<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\RoleController;
use App\Http\Controllers\Api\PermissionController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// Public routes (no authentication required)
Route::prefix('auth')->group(function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// Protected routes (authentication required)
Route::middleware(['custom.auth', 'activity.logger'])->group(function () {
    
    // Auth routes
    Route::prefix('auth')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);
        Route::post('refresh', [AuthController::class, 'refreshToken']);
    });

    // User routes
    Route::prefix('users')->group(function () {
        // List users (requires user management permission)
        Route::get('/', [UserController::class, 'index'])
            ->middleware('permission:users.view');

        // Create user (requires user creation permission)
        Route::post('/', [UserController::class, 'store'])
            ->middleware('permission:users.create');

        // View specific user (requires user view permission)
        Route::get('{id}', [UserController::class, 'show'])
            ->middleware('permission:users.view');

        // Update user (requires user edit permission)
        Route::put('{id}', [UserController::class, 'update'])
            ->middleware('permission:users.edit');

        // Delete user (requires user delete permission)
        Route::delete('{id}', [UserController::class, 'destroy'])
            ->middleware('permission:users.delete');

        // Change user status (requires user edit permission)
        Route::patch('{id}/status', [UserController::class, 'changeStatus'])
            ->middleware('permission:users.edit');

        // Assign role to user (requires user edit permission)
        Route::patch('role/{id}', [UserController::class, 'assignRole'])
            ->middleware('permission:users.edit');

        // Update own profile (any authenticated user)
        Route::put('profile/update', [UserController::class, 'updateProfile']);
    });

    // Role routes
    Route::prefix('roles')->group(function () {
        // List roles (requires role management permission)
        Route::get('/', [RoleController::class, 'index'])
            ->middleware('permission:roles.view');

        // Create role (requires role creation permission)
        Route::post('/', [RoleController::class, 'store'])
            ->middleware('permission:roles.create');

        // View specific role (requires role view permission)
        Route::get('{id}', [RoleController::class, 'show'])
            ->middleware('permission:roles.view');

        // Update role (requires role edit permission)
        Route::put('{id}', [RoleController::class, 'update'])
            ->middleware('permission:roles.edit');

        // Delete role (requires role delete permission)
        Route::delete('{id}', [RoleController::class, 'destroy'])
            ->middleware('permission:roles.delete');

        // Assign permissions to role (requires role edit permission)
        Route::patch('{id}/permissions', [RoleController::class, 'assignPermissions'])
            ->middleware('permission:roles.edit');

        // Get all permissions (requires role view permission)
        Route::get('permissions/all', [RoleController::class, 'getAllPermissions'])
            ->middleware('permission:roles.view');
    });

    // Permission routes
    Route::prefix('permissions')->group(function () {
        // List permissions (requires permission management permission)
        Route::get('/', [PermissionController::class, 'index'])
            ->middleware('permission:permissions.view');

        // Create permission (requires permission creation permission)
        Route::post('/', [PermissionController::class, 'store'])
            ->middleware('permission:permissions.create');

        // Bulk create permissions (requires permission creation permission)
        Route::post('bulk', [PermissionController::class, 'bulkCreate'])
            ->middleware('permission:permissions.create');

        // View specific permission (requires permission view permission)
        Route::get('{id}', [PermissionController::class, 'show'])
            ->middleware('permission:permissions.view');

        // Update permission (requires permission edit permission)
        Route::put('{id}', [PermissionController::class, 'update'])
            ->middleware('permission:permissions.edit');

        // Delete permission (requires permission delete permission)
        Route::delete('{id}', [PermissionController::class, 'destroy'])
            ->middleware('permission:permissions.delete');

        // Get modules (requires permission view permission)
        Route::get('modules/list', [PermissionController::class, 'getModules'])
            ->middleware('permission:permissions.view');
    });

    // Dashboard and reporting routes
    Route::prefix('dashboard')->group(function () {
        // Dashboard stats (requires dashboard access)
        Route::get('stats', function (Request $request) {
            try {
                $stats = \App\Models\ReportsData::getDashboardStats();
                
                return response()->json([
                    'success' => true,
                    'data' => $stats,
                    'message' => 'Dashboard stats retrieved successfully'
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to retrieve dashboard stats',
                    'error' => $e->getMessage()
                ], 500);
            }
        })->middleware('permission:dashboard.view');

        // User reports (requires reports access)
        Route::get('reports/users', function (Request $request) {
            try {
                $users = \App\Models\ReportsData::getActiveUsers();
                
                return response()->json([
                    'success' => true,
                    'data' => $users,
                    'message' => 'User reports retrieved successfully'
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to retrieve user reports',
                    'error' => $e->getMessage()
                ], 500);
            }
        })->middleware('permission:reports.view');

        // Role reports (requires reports access)
        Route::get('reports/roles', function (Request $request) {
            try {
                $roles = \App\Models\ReportsData::getRoles();
                
                return response()->json([
                    'success' => true,
                    'data' => $roles,
                    'message' => 'Role reports retrieved successfully'
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to retrieve role reports',
                    'error' => $e->getMessage()
                ], 500);
            }
        })->middleware('permission:reports.view');
    });

    // Activity logs routes (super admin only)
    Route::prefix('logs')->group(function () {
        Route::get('activity', function (Request $request) {
            try {
                $query = \App\Models\ActivityLog::query();

                // Filter by user
                if ($request->has('user_id')) {
                    $query->where('user_id', $request->user_id);
                }

                // Filter by action
                if ($request->has('action')) {
                    $query->where('action', 'like', '%' . $request->action . '%');
                }

                // Filter by date range
                if ($request->has('from_date')) {
                    $query->whereDate('created_at', '>=', $request->from_date);
                }

                if ($request->has('to_date')) {
                    $query->whereDate('created_at', '<=', $request->to_date);
                }

                $perPage = $request->get('per_page', 15);
                $logs = $query->orderBy('created_at', 'desc')->paginate($perPage);

                return response()->json([
                    'success' => true,
                    'data' => $logs,
                    'message' => 'Activity logs retrieved successfully'
                ], 200);

            } catch (\Exception $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to retrieve activity logs',
                    'error' => $e->getMessage()
                ], 500);
            }
        })->middleware('permission:logs.view');
    });
});