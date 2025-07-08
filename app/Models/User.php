<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use App\Models\Role;
use App\Models\ReportsData;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, SoftDeletes;

    protected $connection = 'main';
    protected $table = 'users';

    protected $fillable = [
        'name',
        'email',
        'password',
        'role_id',
        'status',
        'last_login_at',
        'avatar',
        'preferences',
        'email_verified_at'
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'last_login_at' => 'datetime',
        'preferences' => 'array',
        'password' => 'hashed',
    ];

    // Relationship with Role
    public function role()
    {
        return $this->belongsTo(Role::class);
    }

    // Check if user has specific permission
    public function hasPermission($permission)
    {
        if (!$this->role) {
            return false;
        }

        $permissions = $this->role->permissions ?? [];
        return in_array($permission, $permissions);
    }

    // Check if user has any of the given permissions
    public function hasAnyPermission($permissions)
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }
        return false;
    }

    // Check if user has all given permissions
    public function hasAllPermissions($permissions)
    {
        foreach ($permissions as $permission) {
            if (!$this->hasPermission($permission)) {
                return false;
            }
        }
        return true;
    }

    // Get user permissions array
    public function getPermissions()
    {
        return $this->role ? $this->role->permissions : [];
    }

    // Boot method to sync with reports database
    protected static function booted()
    {
        static::created(function ($user) {
            $user->syncToReportsDatabase();
        });

        static::updated(function ($user) {
            $user->syncToReportsDatabase();
        });

        static::deleted(function ($user) {
            $user->syncToReportsDatabase();
        });
    }

    // Sync user data to reports database
    public function syncToReportsDatabase()
    {
        try {
            // Load role relationship
            $this->load('role');

            $reportData = [
                'type' => 'user',
                'name' => $this->name,
                'email' => $this->email,
                'email_verified_at' => $this->email_verified_at,
                'last_login_at' => $this->last_login_at,
                'avatar' => $this->avatar,
                'preferences' => $this->preferences,
                'permissions' => $this->getPermissions(),
                'role_id' => $this->role_id,
                'role_name' => $this->role ? $this->role->name : null,
                'status' => $this->status,
                'is_active' => $this->status === 'active',
                'created_at' => $this->created_at,
                'updated_at' => $this->updated_at,
                'deleted_at' => $this->deleted_at,
                'synced_at' => now(),
            ];

            // Check if record exists in reports database
            $existingReport = ReportsData::where('type', 'user')
                ->where('email', $this->email)
                ->first();

            if ($existingReport) {
                $existingReport->update($reportData);
            } else {
                ReportsData::create($reportData);
            }

        } catch (\Exception $e) {
            \Log::error('Failed to sync user to reports database: ' . $e->getMessage());
        }
    }
}