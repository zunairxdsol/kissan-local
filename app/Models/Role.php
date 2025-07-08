<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use App\Models\User;
use App\Models\Permission;
use App\Models\ReportsData;

class Role extends Model
{
    use HasFactory;

    protected $connection = 'main';
    protected $table = 'roles';

    protected $fillable = [
        'name',
        'description',
        'permissions',
        'is_active'
    ];

    protected $casts = [
        'permissions' => 'array',
        'is_active' => 'boolean',
    ];

    // Relationship with Users
    public function users()
    {
        return $this->hasMany(User::class);
    }

    // Get users count for this role
    public function getUsersCountAttribute()
    {
        return $this->users()->count();
    }

    // Check if role has specific permission
    public function hasPermission($permission)
    {
        $permissions = $this->permissions ?? [];
        return in_array($permission, $permissions);
    }

    // Add permission to role
    public function addPermission($permission)
    {
        $permissions = $this->permissions ?? [];
        if (!in_array($permission, $permissions)) {
            $permissions[] = $permission;
            $this->permissions = $permissions;
            $this->save();
        }
    }

    // Remove permission from role
    public function removePermission($permission)
    {
        $permissions = $this->permissions ?? [];
        $permissions = array_diff($permissions, [$permission]);
        $this->permissions = array_values($permissions);
        $this->save();
    }

    // Sync permissions with permission names
    public function syncPermissions($permissionNames)
    {
        $this->permissions = $permissionNames;
        $this->save();
    }

    // Boot method to sync with reports database
    protected static function booted()
    {
        static::created(function ($role) {
            $role->syncToReportsDatabase();
        });

        static::updated(function ($role) {
            $role->syncToReportsDatabase();
        });

        static::deleted(function ($role) {
            $role->syncToReportsDatabase();
        });
    }

    // Sync role data to reports database
    public function syncToReportsDatabase()
    {
        try {
            $reportData = [
                'type' => 'role',
                'name' => $this->name,
                'description' => $this->description,
                'permissions_json' => $this->permissions,
                'permissions_list' => $this->permissions,
                'users_count' => $this->users()->count(),
                'status' => $this->is_active ? 'active' : 'inactive',
                'is_active' => $this->is_active,
                'created_at' => $this->created_at,
                'updated_at' => $this->updated_at,
                'synced_at' => now(),
            ];

            // Check if record exists in reports database
            $existingReport = ReportsData::where('type', 'role')
                ->where('name', $this->name)
                ->first();

            if ($existingReport) {
                $existingReport->update($reportData);
            } else {
                ReportsData::create($reportData);
            }

        } catch (\Exception $e) {
            \Log::error('Failed to sync role to reports database: ' . $e->getMessage());
        }
    }
}