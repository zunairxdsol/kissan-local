<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Permission extends Model
{
    use HasFactory;

    protected $connection = 'main';
    protected $table = 'permissions';

    protected $fillable = [
        'name',
        'description',
        'module',
        'action',
        'is_active'
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    // Scope for active permissions
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    // Scope for specific module
    public function scopeModule($query, $module)
    {
        return $query->where('module', $module);
    }

    // Group permissions by module
    public static function groupedByModule()
    {
        return static::active()
            ->orderBy('module')
            ->orderBy('action')
            ->get()
            ->groupBy('module');
    }

    // Get all permission names
    public static function getAllPermissionNames()
    {
        return static::active()->pluck('name')->toArray();
    }

    // Get permissions for specific modules
    public static function getPermissionsForModules($modules)
    {
        return static::active()
            ->whereIn('module', $modules)
            ->pluck('name')
            ->toArray();
    }
}