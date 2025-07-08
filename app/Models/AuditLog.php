<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    use HasFactory;

    protected $connection = 'audit_logs';
    protected $table = 'audit_logs';
    
    const UPDATED_AT = null; // We only use created_at

    protected $fillable = [
        'user_id',
        'table_name',
        'record_id',
        'action',
        'old_values',
        'new_values',
        'changed_fields',
        'ip_address',
        'user_agent',
        'reason',
        'created_at'
    ];

    protected $casts = [
        'old_values' => 'array',
        'new_values' => 'array',
        'changed_fields' => 'array',
        'created_at' => 'datetime',
    ];

    // Create audit log entry
    public static function createAudit($data)
    {
        return static::create([
            'user_id' => $data['user_id'] ?? auth()->id(),
            'table_name' => $data['table_name'],
            'record_id' => $data['record_id'],
            'action' => $data['action'], // create, update, delete, restore
            'old_values' => $data['old_values'] ?? null,
            'new_values' => $data['new_values'] ?? null,
            'changed_fields' => $data['changed_fields'] ?? null,
            'ip_address' => $data['ip_address'] ?? request()->ip(),
            'user_agent' => $data['user_agent'] ?? request()->userAgent(),
            'reason' => $data['reason'] ?? null,
            'created_at' => now(),
        ]);
    }

    // Log model creation
    public static function logCreate($model, $userId = null, $reason = null)
    {
        return static::createAudit([
            'user_id' => $userId ?? auth()->id(),
            'table_name' => $model->getTable(),
            'record_id' => $model->getKey(),
            'action' => 'create',
            'new_values' => $model->getAttributes(),
            'reason' => $reason,
        ]);
    }

    // Log model update
    public static function logUpdate($model, $oldValues, $userId = null, $reason = null)
    {
        $newValues = $model->getAttributes();
        $changedFields = [];
        
        foreach ($newValues as $key => $value) {
            if (isset($oldValues[$key]) && $oldValues[$key] != $value) {
                $changedFields[] = $key;
            }
        }

        if (!empty($changedFields)) {
            return static::createAudit([
                'user_id' => $userId ?? auth()->id(),
                'table_name' => $model->getTable(),
                'record_id' => $model->getKey(),
                'action' => 'update',
                'old_values' => $oldValues,
                'new_values' => $newValues,
                'changed_fields' => $changedFields,
                'reason' => $reason,
            ]);
        }

        return null;
    }

    // Log model deletion
    public static function logDelete($model, $userId = null, $reason = null)
    {
        return static::createAudit([
            'user_id' => $userId ?? auth()->id(),
            'table_name' => $model->getTable(),
            'record_id' => $model->getKey(),
            'action' => 'delete',
            'old_values' => $model->getAttributes(),
            'reason' => $reason,
        ]);
    }

    // Log model restoration (if using soft deletes)
    public static function logRestore($model, $userId = null, $reason = null)
    {
        return static::createAudit([
            'user_id' => $userId ?? auth()->id(),
            'table_name' => $model->getTable(),
            'record_id' => $model->getKey(),
            'action' => 'restore',
            'new_values' => $model->getAttributes(),
            'reason' => $reason,
        ]);
    }

    // Get audit history for a specific record
    public static function getRecordHistory($tableName, $recordId)
    {
        return static::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('created_at', 'desc')
            ->get();
    }

    // Get user's audit history
    public static function getUserHistory($userId, $limit = 50)
    {
        return static::where('user_id', $userId)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Get audit logs by table
    public static function getTableHistory($tableName, $limit = 100)
    {
        return static::where('table_name', $tableName)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Get audit logs by action
    public static function getActionHistory($action, $limit = 100)
    {
        return static::where('action', $action)
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }

    // Get audit statistics
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
            'total_audits' => $query->count(),
            'by_action' => $query->selectRaw('action, COUNT(*) as count')
                ->groupBy('action')
                ->pluck('count', 'action'),
            'by_table' => $query->selectRaw('table_name, COUNT(*) as count')
                ->groupBy('table_name')
                ->orderBy('count', 'desc')
                ->pluck('count', 'table_name'),
            'by_user' => $query->selectRaw('user_id, COUNT(*) as count')
                ->whereNotNull('user_id')
                ->groupBy('user_id')
                ->orderBy('count', 'desc')
                ->pluck('count', 'user_id'),
        ];
    }

    // Relationship with User
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}