<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Services\LoggingService;

class DatabaseServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(LoggingService::class, function ($app) {
            return new LoggingService();
        });
    }

    public function boot()
    {
        // Test database connections on boot
        $this->testDatabaseConnections();
        
        // Enable query logging if configured
        if (config('app.env') === 'local' || env('ENABLE_QUERY_LOGGING', false)) {
            $this->enableQueryLogging();
        }
    }

    protected function testDatabaseConnections()
    {
        $connections = ['main', 'error_logs', 'activity_logs', 'audit_logs', 'reports_logs'];
        
        foreach ($connections as $connection) {
            try {
                DB::connection($connection)->getPdo();
                Log::info("Database connection '{$connection}' established successfully");
            } catch (\Exception $e) {
                Log::error("Failed to connect to database '{$connection}': " . $e->getMessage());
            }
        }
    }

    protected function enableQueryLogging()
    {
        DB::listen(function (QueryExecuted $query) {
            if (env('ENABLE_PERFORMANCE_LOGGING', false)) {
                Log::channel('database')->info('Query executed', [
                    'connection' => $query->connectionName,
                    'query' => $query->sql,
                    'bindings' => $query->bindings,
                    'time' => $query->time . 'ms'
                ]);
            }
        });
    }
}