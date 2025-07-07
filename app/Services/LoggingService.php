<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;

class LoggingService
{
    public function logError($userId, $errorType, $message, $stackTrace = null, Request $request = null)
    {
        try {
            DB::connection('error_logs')->table('error_logs')->insert([
                'user_id' => $userId,
                'error_type' => $errorType,
                'message' => $message,
                'stack_trace' => $stackTrace,
                'request_data' => $request ? json_encode($request->all()) : null,
                'ip_address' => $request ? $request->ip() : null,
                'user_agent' => $request ? $request->header('User-Agent') : null,
                'created_at' => now(),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to log error to database: ' . $e->getMessage());
        }
    }

    public function logActivity($userId, $action, $tableName = null, $recordId = null, $authToken = null, Request $request = null)
    {
        try {
            DB::connection('activity_logs')->table('activity_logs')->insert([
                'user_id' => $userId,
                'action' => $action,
                'table_name' => $tableName,
                'record_id' => $recordId,
                'auth_token' => $authToken,
                'ip_address' => $request ? $request->ip() : null,
                'user_agent' => $request ? $request->header('User-Agent') : null,
                'created_at' => now(),
                'expires_at' => $authToken ? now()->addHours(config('auth.token_expiry_hours', 24)) : null,
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to log activity to database: ' . $e->getMessage());
        }
    }

    public function logAudit($userId, $tableName, $recordId, $action, $oldValues = null, $newValues = null)
    {
        try {
            DB::connection('audit_logs')->table('audit_logs')->insert([
                'user_id' => $userId,
                'table_name' => $tableName,
                'record_id' => $recordId,
                'action' => $action,
                'old_values' => $oldValues ? json_encode($oldValues) : null,
                'new_values' => $newValues ? json_encode($newValues) : null,
                'created_at' => now(),
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to log audit to database: ' . $e->getMessage());
        }
    }

    public function cleanupOldLogs($days = 30)
    {
        $cutoffDate = now()->subDays($days);
        
        try {
            DB::connection('error_logs')->table('error_logs')
                ->where('created_at', '<', $cutoffDate)
                ->delete();
                
            DB::connection('activity_logs')->table('activity_logs')
                ->where('created_at', '<', $cutoffDate)
                ->whereNull('auth_token') // Don't delete token records
                ->delete();
                
            DB::connection('audit_logs')->table('audit_logs')
                ->where('created_at', '<', $cutoffDate)
                ->delete();
                
            Log::info("Cleaned up logs older than {$days} days");
        } catch (\Exception $e) {
            Log::error('Failed to cleanup old logs: ' . $e->getMessage());
        }
    }
}