<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\RoleController;
use App\Http\Controllers\Api\PermissionController;
use App\Http\Controllers\LogController;

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

        // Bulk update users (requires user edit permission)
        Route::put('bulk', [UserController::class, 'bulkUpdate'])
            ->middleware('permission:users.edit');

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
        Route::patch('{id}/role', [UserController::class, 'assignRole'])
            ->middleware('permission:users.edit');

        // Get user audit history (requires user view permission)
        Route::get('{id}/audit-history', [UserController::class, 'getUserAuditHistory'])
            ->middleware('permission:users.view');

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

        // Bulk update permissions (requires permission edit permission)
        Route::put('bulk', [PermissionController::class, 'bulkUpdate'])
            ->middleware('permission:permissions.edit');

        // Bulk delete permissions (requires permission delete permission)
        Route::delete('bulk', [PermissionController::class, 'bulkDelete'])
            ->middleware('permission:permissions.delete');

        // View specific permission (requires permission view permission)
        Route::get('{id}', [PermissionController::class, 'show'])
            ->middleware('permission:permissions.view');

        // Update permission (requires permission edit permission)
        Route::put('{id}', [PermissionController::class, 'update'])
            ->middleware('permission:permissions.edit');

        // Delete permission (requires permission delete permission)
        Route::delete('{id}', [PermissionController::class, 'destroy'])
            ->middleware('permission:permissions.delete');

        // Toggle permission status (requires permission edit permission)
        Route::patch('{id}/status', [PermissionController::class, 'toggleStatus'])
            ->middleware('permission:permissions.edit');

        // Search permissions (requires permission view permission)
        Route::get('search', [PermissionController::class, 'search'])
            ->middleware('permission:permissions.view');

        // Get permission statistics (requires permission view permission)
        Route::get('statistics', [PermissionController::class, 'getStatistics'])
            ->middleware('permission:permissions.view');

        // Get modules (requires permission view permission)
        Route::get('modules/list', [PermissionController::class, 'getModules'])
            ->middleware('permission:permissions.view');

        // Get actions (requires permission view permission)
        Route::get('actions/list', [PermissionController::class, 'getActions'])
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
                \App\Models\ErrorLog::logException($e, $request->user()->id);
                
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
                \App\Models\ErrorLog::logException($e, $request->user()->id);
                
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
                \App\Models\ErrorLog::logException($e, $request->user()->id);
                
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to retrieve role reports',
                    'error' => $e->getMessage()
                ], 500);
            }
        })->middleware('permission:reports.view');
    });

    // Comprehensive Logging routes
    Route::prefix('logs')->group(function () {
        
        // Activity logs (existing functionality)
        Route::get('activity', [LogController::class, 'getActivityLogs'])
            ->middleware('permission:logs.view');

        // Audit logs
        Route::get('audit', [LogController::class, 'getAuditLogs'])
            ->middleware('permission:logs.view');

        // Error logs
        Route::get('error', [LogController::class, 'getErrorLogs'])
            ->middleware('permission:logs.view');

        // Get record audit history
        Route::get('audit/record/{tableName}/{recordId}', [LogController::class, 'getRecordAuditHistory'])
            ->middleware('permission:logs.view');

        // Error statistics
        Route::get('error/statistics', [LogController::class, 'getErrorStatistics'])
            ->middleware('permission:logs.view');

        // Audit statistics
        Route::get('audit/statistics', [LogController::class, 'getAuditStatistics'])
            ->middleware('permission:logs.view');

        // Critical errors
        Route::get('error/critical', [LogController::class, 'getCriticalErrors'])
            ->middleware('permission:logs.view');

        // Errors by type
        Route::get('error/type/{errorType}', [LogController::class, 'getErrorsByType'])
            ->middleware('permission:logs.view');

        // Log summary dashboard
        Route::get('summary', [LogController::class, 'getLogSummary'])
            ->middleware('permission:logs.view');

        // Export logs
        Route::get('export', [LogController::class, 'exportLogs'])
            ->middleware('permission:logs.export');

        // Clean old logs (admin only)
        Route::post('clean', [LogController::class, 'cleanOldLogs'])
            ->middleware('permission:logs.admin');
    });
});