<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\ProductController;
use App\Http\Controllers\Api\RoleController;

Route::prefix('v1')->group(function () {
    // Authentication routes
    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);
    
    // Protected routes
    Route::middleware('auth:api')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('user', [AuthController::class, 'user']);
        Route::post('refresh-token', [AuthController::class, 'refreshToken']);
        
        // User management
        Route::apiResource('users', UserController::class);
        
        // Product management
        Route::apiResource('products', ProductController::class);
        
        // Role and permission management
        Route::apiResource('roles', RoleController::class);
        Route::get('permissions', [RoleController::class, 'permissions']);
        Route::post('sync-permissions', [RoleController::class, 'syncPermissions']);
    });
});

// Health check
Route::get('health', function () {
    return response()->json([
        'status' => 'OK',
        'timestamp' => now(),
        'databases' => [
            'main' => DB::connection('main')->getPdo() ? 'connected' : 'disconnected',
            'error_logs' => DB::connection('error_logs')->getPdo() ? 'connected' : 'disconnected',
            'activity_logs' => DB::connection('activity_logs')->getPdo() ? 'connected' : 'disconnected',
            'audit_logs' => DB::connection('audit_logs')->getPdo() ? 'connected' : 'disconnected',
            'reports_logs' => DB::connection('reports_logs')->getPdo() ? 'connected' : 'disconnected',
        ]
    ]);
});
