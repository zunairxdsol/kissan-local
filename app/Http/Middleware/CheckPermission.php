<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\ActivityLog;

class CheckPermission
{
    public function handle(Request $request, Closure $next, ...$permissions)
    {
      
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized'
            ], 401);
        }

        // Check if user has any of the required permissions
        if (!empty($permissions)) {
            $hasPermission = false;

            foreach ($permissions as $permission) {
                if ($user->hasPermission($permission)) {
                    $hasPermission = true;
                    break;
                }
            }

            if (!$hasPermission) {
                // Log unauthorized access attempt
                ActivityLog::createLog([
                    'user_id' => $user->id,
                    'action' => 'unauthorized_access_attempt',
                    'request_data' => [
                        'required_permissions' => $permissions,
                        'user_permissions' => $user->getPermissions(),
                        'url' => $request->url(),
                        'method' => $request->method(),
                    ],
                    'response_status' => 403,
                ]);

                return response()->json([
                    'success' => false,
                    'message' => 'Insufficient permissions'
                ], 403);
            }
        }

        return $next($request);
    }
}