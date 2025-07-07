<?php

use Illuminate\Support\Str;

return [
    'default' => env('DB_CONNECTION', 'main'),
    
    'connections' => [
        'main' => [
            'driver' => 'mysql',
            'host' => env('DB_MAIN_HOST', '127.0.0.1'),
            'port' => env('DB_MAIN_PORT', '3306'),
            'database' => env('DB_MAIN_DATABASE', 'main_database'),
            'username' => env('DB_MAIN_USERNAME', 'main_user'),
            'password' => env('DB_MAIN_PASSWORD', ''),
            'unix_socket' => env('DB_MAIN_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
            'options' => extension_loaded('pdo_mysql') ? array_filter([
                PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
            ]) : [],
        ],
        
        'error_logs' => [
            'driver' => 'mysql',
            'host' => env('DB_ERROR_HOST', '127.0.0.1'),
            'port' => env('DB_ERROR_PORT', '3306'),
            'database' => env('DB_ERROR_DATABASE', 'error_logs'),
            'username' => env('DB_ERROR_USERNAME', 'error_user'),
            'password' => env('DB_ERROR_PASSWORD', ''),
            'unix_socket' => env('DB_ERROR_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
        ],
        
        'activity_logs' => [
            'driver' => 'mysql',
            'host' => env('DB_ACTIVITY_HOST', '127.0.0.1'),
            'port' => env('DB_ACTIVITY_PORT', '3306'),
            'database' => env('DB_ACTIVITY_DATABASE', 'activity_logs'),
            'username' => env('DB_ACTIVITY_USERNAME', 'activity_user'),
            'password' => env('DB_ACTIVITY_PASSWORD', ''),
            'unix_socket' => env('DB_ACTIVITY_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
        ],
        
        'audit_logs' => [
            'driver' => 'mysql',
            'host' => env('DB_AUDIT_HOST', '127.0.0.1'),
            'port' => env('DB_AUDIT_PORT', '3306'),
            'database' => env('DB_AUDIT_DATABASE', 'audit_logs'),
            'username' => env('DB_AUDIT_USERNAME', 'audit_user'),
            'password' => env('DB_AUDIT_PASSWORD', ''),
            'unix_socket' => env('DB_AUDIT_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
        ],
        
        'reports_logs' => [
            'driver' => 'mysql',
            'host' => env('DB_REPORTS_HOST', '127.0.0.1'),
            'port' => env('DB_REPORTS_PORT', '3306'),
            'database' => env('DB_REPORTS_DATABASE', 'reports_logs'),
            'username' => env('DB_REPORTS_USERNAME', 'reports_readonly'),
            'password' => env('DB_REPORTS_PASSWORD', ''),
            'unix_socket' => env('DB_REPORTS_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'prefix_indexes' => true,
            'strict' => true,
            'engine' => null,
        ],
    ],
    
    'migrations' => 'migrations',
    'redis' => [
        'client' => env('REDIS_CLIENT', 'phpredis'),
        'options' => [
            'cluster' => env('REDIS_CLUSTER', 'redis'),
            'prefix' => env('REDIS_PREFIX', Str::slug(env('APP_NAME', 'laravel'), '_').'_database_'),
        ],
        'default' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
        ],
        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
        ],
    ],
];