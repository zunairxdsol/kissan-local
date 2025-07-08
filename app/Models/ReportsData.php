<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ReportsData extends Model
{
    use HasFactory;

    protected $connection = 'reports_logs';
    protected $table = 'reports_data';

    protected $fillable = [
        'type',
        'name',
        'email',
        'slug',
        'description',
        'short_description',
        'price',
        'sale_price',
        'sku',
        'stock_quantity',
        'manage_stock',
        'weight',
        'dimensions',
        'images',
        'attributes',
        'email_verified_at',
        'last_login_at',
        'avatar',
        'preferences',
        'permissions',
        'image',
        'sort_order',
        'products_count',
        'permissions_json',
        'permissions_list',
        'users_count',
        'role_id',
        'role_name',
        'category_id',
        'category_name',
        'category_slug',
        'created_by',
        'creator_name',
        'creator_email',
        'status',
        'is_active',
        'created_at',
        'updated_at',
        'deleted_at',
        'synced_at'
    ];

    protected $casts = [
        'dimensions' => 'array',
        'images' => 'array',
        'attributes' => 'array',
        'preferences' => 'array',
        'permissions' => 'array',
        'permissions_json' => 'array',
        'permissions_list' => 'array',
        'email_verified_at' => 'datetime',
        'last_login_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
        'synced_at' => 'datetime',
        'is_active' => 'boolean',
        'manage_stock' => 'boolean',
        'price' => 'decimal:2',
        'sale_price' => 'decimal:2',
        'weight' => 'decimal:2',
    ];

    // Scope for specific type
    public function scopeType($query, $type)
    {
        return $query->where('type', $type);
    }

    // Scope for active records
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    // Scope for specific status
    public function scopeStatus($query, $status)
    {
        return $query->where('status', $status);
    }

    // Get users from reports
    public static function getUsers()
    {
        return static::type('user')->get();
    }

    // Get roles from reports
    public static function getRoles()
    {
        return static::type('role')->get();
    }

    // Get active users
    public static function getActiveUsers()
    {
        return static::type('user')->active()->get();
    }

    // Get users with specific role
    public static function getUsersByRole($roleId)
    {
        return static::type('user')->where('role_id', $roleId)->get();
    }

    // Get dashboard statistics
    public static function getDashboardStats()
    {
        return [
            'total_users' => static::type('user')->count(),
            'active_users' => static::type('user')->active()->count(),
            'total_roles' => static::type('role')->count(),
            'active_roles' => static::type('role')->active()->count(),
            'recent_users' => static::type('user')
                ->orderBy('created_at', 'desc')
                ->limit(10)
                ->get(),
        ];
    }
}