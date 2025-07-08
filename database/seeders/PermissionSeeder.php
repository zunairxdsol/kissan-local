<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class PermissionSeeder extends Seeder
{
    public function run()
    {
        // Define permissions by module
        $permissions = [
            // User Management
            [
                'name' => 'users.view',
                'description' => 'View users list and details',
                'module' => 'users',
                'action' => 'view'
            ],
            [
                'name' => 'users.create',
                'description' => 'Create new users',
                'module' => 'users',
                'action' => 'create'
            ],
            [
                'name' => 'users.edit',
                'description' => 'Edit existing users',
                'module' => 'users',
                'action' => 'edit'
            ],
            [
                'name' => 'users.delete',
                'description' => 'Delete users',
                'module' => 'users',
                'action' => 'delete'
            ],

            // Role Management
            [
                'name' => 'roles.view',
                'description' => 'View roles list and details',
                'module' => 'roles',
                'action' => 'view'
            ],
            [
                'name' => 'roles.create',
                'description' => 'Create new roles',
                'module' => 'roles',
                'action' => 'create'
            ],
            [
                'name' => 'roles.edit',
                'description' => 'Edit existing roles',
                'module' => 'roles',
                'action' => 'edit'
            ],
            [
                'name' => 'roles.delete',
                'description' => 'Delete roles',
                'module' => 'roles',
                'action' => 'delete'
            ],

            // Permission Management
            [
                'name' => 'permissions.view',
                'description' => 'View permissions list and details',
                'module' => 'permissions',
                'action' => 'view'
            ],
            [
                'name' => 'permissions.create',
                'description' => 'Create new permissions',
                'module' => 'permissions',
                'action' => 'create'
            ],
            [
                'name' => 'permissions.edit',
                'description' => 'Edit existing permissions',
                'module' => 'permissions',
                'action' => 'edit'
            ],
            [
                'name' => 'permissions.delete',
                'description' => 'Delete permissions',
                'module' => 'permissions',
                'action' => 'delete'
            ],

            // Dashboard Access
            [
                'name' => 'dashboard.view',
                'description' => 'Access dashboard',
                'module' => 'dashboard',
                'action' => 'view'
            ],

            // Reports Access
            [
                'name' => 'reports.view',
                'description' => 'View reports',
                'module' => 'reports',
                'action' => 'view'
            ],
            [
                'name' => 'reports.export',
                'description' => 'Export reports',
                'module' => 'reports',
                'action' => 'export'
            ],

            // Logs Access
            [
                'name' => 'logs.view',
                'description' => 'View system logs',
                'module' => 'logs',
                'action' => 'view'
            ],

            // Product Management (for future use)
            [
                'name' => 'products.view',
                'description' => 'View products list and details',
                'module' => 'products',
                'action' => 'view'
            ],
            [
                'name' => 'products.create',
                'description' => 'Create new products',
                'module' => 'products',
                'action' => 'create'
            ],
            [
                'name' => 'products.edit',
                'description' => 'Edit existing products',
                'module' => 'products',
                'action' => 'edit'
            ],
            [
                'name' => 'products.delete',
                'description' => 'Delete products',
                'module' => 'products',
                'action' => 'delete'
            ],

            // Category Management (for future use)
            [
                'name' => 'categories.view',
                'description' => 'View categories list and details',
                'module' => 'categories',
                'action' => 'view'
            ],
            [
                'name' => 'categories.create',
                'description' => 'Create new categories',
                'module' => 'categories',
                'action' => 'create'
            ],
            [
                'name' => 'categories.edit',
                'description' => 'Edit existing categories',
                'module' => 'categories',
                'action' => 'edit'
            ],
            [
                'name' => 'categories.delete',
                'description' => 'Delete categories',
                'module' => 'categories',
                'action' => 'delete'
            ],
        ];

        // Create permissions
        foreach ($permissions as $permission) {
            Permission::firstOrCreate(
                ['name' => $permission['name']],
                $permission
            );
        }

        // Create roles with permissions
        $this->createRoles();
        
        // Create default admin user
        $this->createDefaultUsers();
    }

    private function createRoles()
    {
        // Super Admin Role - has all permissions
        $superAdmin = Role::firstOrCreate(
            ['name' => 'super_admin'],
            [
                'description' => 'Super Administrator with full access',
                'permissions' => Permission::getAllPermissionNames(),
                'is_active' => true
            ]
        );

        // Admin Role - has most permissions except logs
        $adminPermissions = Permission::whereNotIn('module', ['logs'])
            ->pluck('name')
            ->toArray();

        $admin = Role::firstOrCreate(
            ['name' => 'admin'],
            [
                'description' => 'Administrator with limited access',
                'permissions' => $adminPermissions,
                'is_active' => true
            ]
        );

        // Manager Role - can manage users and view reports
        $managerPermissions = [
            'users.view',
            'users.create',
            'users.edit',
            'roles.view',
            'dashboard.view',
            'reports.view',
        ];

        $manager = Role::firstOrCreate(
            ['name' => 'manager'],
            [
                'description' => 'Manager with user management access',
                'permissions' => $managerPermissions,
                'is_active' => true
            ]
        );

        // User Role - basic access
        $userPermissions = [
            'dashboard.view',
        ];

        $user = Role::firstOrCreate(
            ['name' => 'user'],
            [
                'description' => 'Regular user with basic access',
                'permissions' => $userPermissions,
                'is_active' => true
            ]
        );

        // Viewer Role - read-only access
        $viewerPermissions = [
            'users.view',
            'roles.view',
            'permissions.view',
            'dashboard.view',
            'reports.view',
        ];

        $viewer = Role::firstOrCreate(
            ['name' => 'viewer'],
            [
                'description' => 'Viewer with read-only access',
                'permissions' => $viewerPermissions,
                'is_active' => true
            ]
        );
    }

    // private function createDefaultUsers()
    // {
    //     // Get super admin role
    //     $superAdminRole = Role::where('name', 'super_admin')->first();
    //     $adminRole = Role::where('name', 'admin')->first();
    //     $userRole = Role::where('name', 'user')->first();

    //     // Create super admin user
    //     // User::firstOrCreate(
    //     //     ['email' => 'superadmin@example.com'],
    //     //     [
    //     //         'name' => 'Super Administrator',
    //     //         'password' => Hash::make('password123'),
    //     //         'role_id' => $superAdminRole->id,
    //     //         'status' => 'active',
    //     //         'email_verified_at' => now(),
    //     //     ]
    //     // );

    //     // Create admin user
    //     // User::firstOrCreate(
    //     //     ['email' => 'admin@example.com'],
    //     //     [
    //     //         'name' => 'Administrator',
    //     //         'password' => Hash::make('password123'),
    //     //         'role_id' => $adminRole->id,
    //     //         'status' => 'active',
    //     //         'email_verified_at' => now(),
    //     //     ]
    //     // );

    //     // Create regular user
    //     // User::firstOrCreate(
    //     //     ['email' => 'user@example.com'],
    //     //     [
    //     //         'name' => 'Regular User',
    //     //         'password' => Hash::make('password123'),
    //     //         'role_id' => $userRole->id,
    //     //         'status' => 'active',
    //     //         'email_verified_at' => now(),
    //     //     ]
    //     // );
    // }
}