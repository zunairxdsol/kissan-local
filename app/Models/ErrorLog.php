<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ErrorLog extends Model
{
    use HasFactory;

    protected $connection = 'error_logs';
    protected $table = 'error_logs';
    
    const UPDATED_AT = null; // We only use created_at

    protected $fillable = [
        'user_id',
        'error_type',
        'message',
        'stack_trace',
        'request_data',
        'ip_address',
        'user_agent',
        'url',
        'method',
        'status_code',
        'file',
        'line',
        'context',
        'created_at'
    ];

    protected $casts = [
        'request_data' => 'array',
        'context' => 'array',
        'created_at' => 'datetime',
    ];

    // Create error log entry
    public static function createError($data)
    {
        return static::create([
            'user_id' => $data['user_id'] ?? auth()->id(),
            'error_type' => $data['error_type'],
            'message' => $data['message'],
            'stack_trace' => $data['stack_trace'] ?? null,
            'request_data' => $data['request_data'] ?? null,
            'ip_address' => $data['ip_address'] ?? request()->ip(),
            'user_agent' => $data['user_agent'] ?? request()->userAgent(),
            'url' => $data['url'] ?? request()->fullUrl(),
            'method' => $data['method'] ?? request()->method(),
            'status_code' => $data['status_code'] ?? null,
            'file' => $data['file'] ?? null,
            'line' => $data['line'] ?? null,
            'context' => $data['context'] ?? null,
            'created_at' => now(),
        ]);
    }

    // Log exception
    public static function logException(\Exception $exception, $userId = null, $context = null)
    {
        return static::createError([
            'user_id' => $userId ?? auth()->id(),
            'error_type' => get_class($exception),
            'message' => $exception->getMessage(),
            'stack_trace' => $exception->getTraceAsString(),
            'request_data' => request()->all(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'context' => $context,
            'status_code' => method_exists($exception, 'getStatusCode') ? $exception->getStatusCode() : 500,
        ]);
    }

    // Log validation error
    public static function logValidationError($errors, $userId = null)
    {
        return static::createError([
            'user_id' => $userId ?? auth()->id(),
            'error_type' => 'ValidationException',
            'message' => 'Validation failed',
            'request_data' => request()->all(),
            'context' => ['validation_errors' => $errors],
            'status_code' => 422,
        ]);
    }

    // Log authentication error
    public static function logAuthError($message, $userId = null)
    {
        return static::createError([
            'user_id' => $userId,
            'error_type' => 'AuthenticationException',
            'message' => $message,
            'request_data' => request()->all(),
            'status_code' => 401,
        ]);
    }

    // Log authorization error
    public static function logAuthorizationError($message, $userId = null)
    {
        return static::createError([
            'user_id' => $userId ?? auth()->id(),
            'error_type' => 'AuthorizationException',
            'message' => $message,
            'request_data' => request()->all(),
            'status_code' => 403,
        ]);
    }

    // Log database error
    public static function logDatabaseError(\Exception $exception, $userId = null)
    {
        return static::createError([
            'user_id' => $userId ?? auth()->id(),
            'error_type' => 'DatabaseException',
            'message' => $exception->getMessage(),
            'stack_trace' => $exception->getTraceAsString(),
            'request_data' => request()->all(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'status_code' => 500,
        ]);
    }

    // Log API error
    public static function logApiError($message, $statusCode, $userId = null, $context = null)
    {
        return static::createError([
            'user_id' => $userId ?? auth()->id(),
            'error_type' => 'ApiException',
            'message' => $message,
            'request_data' => request()->all(),
            'status_code' => $statusCode,
            'context' => $context,
        ]);
    }

    // Get error statistics
    public static function getStatistics($startDate = null, $endDate = null)
    {
        $query = static::query();
        
        if ($startDate) {
            $query->where('created_at', '>=', $startDate);
        }
        
        if ($endDate) {
            $query->where('created_at', '<=', $endDate);
        }

        return [
            'total_errors' => $query->count(),
            'by_type' => $query->selectRaw('error_type, COUNT(*) as count')
                ->groupBy('error_type')
                ->orderBy('count', 'desc')
                ->pluck('count', 'error_type'),
            'by_status_code' => $query->selectRaw('status_code, COUNT(*) as count')
                ->whereNotNull('status_code')
                ->groupBy('status_code')
                ->orderBy('count', 'desc')
                ->pluck('count', 'status_code'),
            'by_user' => $query->selectRaw('user_id, COUNT(*) as count')
                ->whereNotNull('user_id')
                ->groupBy('user_id')
                ->orderBy('count', 'desc')
                ->limit(10)
                ->pluck('count', 'user_id'),
            'recent_errors' => $query->orderBy('created_at', 'desc')
                ->limit(10)
                ->get(['error_type', 'message', 'status_code', 'created_at']),
        ];
    }

    // Get errors by type
    public static function getErrorsByType($errorType, $limit = 50)
    {
        return static::where('error_type', $errorType)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Get errors by status code
    public static function getErrorsByStatusCode($statusCode, $limit = 50)
    {
        return static::where('status_code', $statusCode)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Get user's error history
    public static function getUserErrors($userId, $limit = 50)
    {
        return static::where('user_id', $userId)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Clean old error logs (older than specified days)
    public static function cleanOldLogs($days = 30)
    {
        return static::where('created_at', '<', now()->subDays($days))->delete();
    }

    // Get critical errors (5xx status codes)
    public static function getCriticalErrors($limit = 50)
    {
        return static::whereBetween('status_code', [500, 599])
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Relationship with User
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}