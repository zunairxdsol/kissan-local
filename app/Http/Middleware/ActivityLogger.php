<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\ActivityLog;

class ActivityLogger
{
    public function handle(Request $request, Closure $next)
    {
        $startTime = microtime(true);

        $response = $next($request);

        $endTime = microtime(true);
        $responseTime = ($endTime - $startTime) * 1000; // Convert to milliseconds

        // Log the activity
        $this->logActivity($request, $response, $responseTime);

        return $response;
    }

    private function logActivity($request, $response, $responseTime)
    {
        try {
            $user = $request->user();
            $token = $request->bearerToken();

            // Determine action based on route
            $action = $this->determineAction($request);

            // Get request data (excluding sensitive information)
            $requestData = $this->sanitizeRequestData($request->all());

            // Get response data (limit size)
            $responseData = $this->getResponseData($response);

            ActivityLog::createLog([
                'user_id' => $user ? $user->id : null,
                'action' => $action,
                'auth_token' => $token,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'response_status' => $response->getStatusCode(),
                'response_time' => round($responseTime, 3),
                'session_id' => session()->getId(),
            ]);

        } catch (\Exception $e) {
            // Log error but don't break the request
            \Log::error('Failed to log activity: ' . $e->getMessage());
        }
    }

    private function determineAction($request)
    {
        $route = $request->route();
        
        if (!$route) {
            return $request->method() . '_' . str_replace('/', '_', trim($request->getPathInfo(), '/'));
        }

        $routeName = $route->getName();
        
        if ($routeName) {
            return $routeName;
        }

        // Fallback to method + path
        $method = strtolower($request->method());
        $path = str_replace('/', '_', trim($request->getPathInfo(), '/'));
        
        return $method . '_' . $path;
    }

    private function sanitizeRequestData($data)
    {
        // Remove sensitive fields
        $sensitiveFields = [
            'password',
            'password_confirmation',
            'current_password',
            'token',
            'api_key',
            'secret',
        ];

        foreach ($sensitiveFields as $field) {
            if (isset($data[$field])) {
                $data[$field] = '[HIDDEN]';
            }
        }

        // Limit data size
        $jsonData = json_encode($data);
        if (strlen($jsonData) > 65535) { // MySQL TEXT limit
            return ['message' => 'Request data too large to store'];
        }

        return $data;
    }

    private function getResponseData($response)
    {
        try {
            $content = $response->getContent();
            
            // Only log JSON responses
            if (!$this->isJson($content)) {
                return null;
            }

            $data = json_decode($content, true);
            
            // Limit response data size
            $jsonData = json_encode($data);
            if (strlen($jsonData) > 65535) { // MySQL TEXT limit
                return [
                    'message' => 'Response data too large to store',
                    'size' => strlen($jsonData),
                ];
            }

            return $data;

        } catch (\Exception $e) {
            return ['error' => 'Failed to parse response data'];
        }
    }

    private function isJson($string)
    {
        json_decode($string);
        return json_last_error() === JSON_ERROR_NONE;
    }
}