<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ActivityLog extends Model
{
    use HasFactory;

    protected $connection = 'activity_logs';
    protected $table = 'activity_logs';
    
    const UPDATED_AT = null; // We only use created_at

    protected $fillable = [
        'user_id',
        'action',
        'table_name',
        'record_id',
        'auth_token',
        'ip_address',
        'user_agent',
        'request_data',
        'response_data',
        'response_status',
        'response_time',
        'session_id',
        'created_at',
        'expires_at'
    ];

    protected $casts = [
        'request_data' => 'array',
        'response_data' => 'array',
        'created_at' => 'datetime',
        'expires_at' => 'datetime',
        'response_time' => 'decimal:3',
    ];

    // Create activity log entry
    public static function createLog($data)
    {
        return static::create([
            'user_id' => $data['user_id'] ?? null,
            'action' => $data['action'],
            'table_name' => $data['table_name'] ?? null,
            'record_id' => $data['record_id'] ?? null,
            'auth_token' => $data['auth_token'] ?? null,
            'ip_address' => $data['ip_address'] ?? request()->ip(),
            'user_agent' => $data['user_agent'] ?? request()->userAgent(),
            'request_data' => $data['request_data'] ?? null,
            'response_data' => $data['response_data'] ?? null,
            'response_status' => $data['response_status'] ?? null,
            'response_time' => $data['response_time'] ?? null,
            'session_id' => $data['session_id'] ?? null,
            'expires_at' => $data['expires_at'] ?? null,
            'created_at' => now(),
        ]);
    }

    // Log user login
    public static function logLogin($user, $token, $expiresAt = null)
    {
        return static::createLog([
            'user_id' => $user->id,
            'action' => 'login',
            'auth_token' => $token,
            'expires_at' => $expiresAt,
            'response_status' => 200,
        ]);
    }

    // Log user logout
    public static function logLogout($user, $token)
    {
        return static::createLog([
            'user_id' => $user->id,
            'action' => 'logout',
            'auth_token' => $token,
            'response_status' => 200,
        ]);
    }

    // Log API request
    public static function logApiRequest($user, $action, $requestData = null, $responseData = null, $responseStatus = 200, $responseTime = null)
    {
        return static::createLog([
            'user_id' => $user ? $user->id : null,
            'action' => $action,
            'request_data' => $requestData,
            'response_data' => $responseData,
            'response_status' => $responseStatus,
            'response_time' => $responseTime,
        ]);
    }

    // Get active tokens
    public static function getActiveTokens()
    {
        return static::whereNotNull('auth_token')
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->get();
    }

    // Get user's active tokens
    public static function getUserActiveTokens($userId)
    {
        return static::where('user_id', $userId)
            ->whereNotNull('auth_token')
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->get();
    }

    // Invalidate token
    public static function invalidateToken($token)
    {
        return static::where('auth_token', $token)->update(['expires_at' => now()]);
    }

    // Check if token is valid
    public static function isTokenValid($token)
    {
        return static::where('auth_token', $token)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }

    // Get user by token
    public static function getUserByToken($token)
    {
        $log = static::where('auth_token', $token)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->first();

        return $log ? User::find($log->user_id) : null;
    }

    // Clean expired tokens
    public static function cleanExpiredTokens()
    {
        return static::where('expires_at', '<', now())
            ->whereNotNull('auth_token')
            ->update(['auth_token' => null]);
    }
}