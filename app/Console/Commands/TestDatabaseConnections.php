<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class TestDatabaseConnections extends Command
{
    protected $signature = 'db:test-connections';
    protected $description = 'Test all database connections';

    public function handle()
    {
        $connections = ['main', 'error_logs', 'activity_logs', 'audit_logs', 'reports_logs'];
        
        $this->info('Testing database connections...');
        
        foreach ($connections as $connection) {
            try {
                DB::connection($connection)->getPdo();
                $this->info("✓ {$connection} - Connected successfully");
            } catch (\Exception $e) {
                $this->error("✗ {$connection} - Failed: " . $e->getMessage());
            }
        }
    }
}