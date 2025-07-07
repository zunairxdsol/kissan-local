<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class SetupDatabases extends Command
{
    protected $signature = 'db:setup-multi';
    protected $description = 'Setup multiple databases and users';

    public function handle()
    {
        $this->info('Setting up multiple databases...');
        
        $databases = [
            'main_database' => 'main_user',
            'error_logs' => 'error_user',
            'activity_logs' => 'activity_user',
            'audit_logs' => 'audit_user',
            'reports_logs' => 'reports_readonly'
        ];
        
        foreach ($databases as $database => $user) {
            $this->createDatabase($database, $user);
        }
        
        $this->info('Database setup completed!');
    }
    
    private function createDatabase($database, $user)
    {
        try {
            // Create database
            DB::statement("CREATE DATABASE IF NOT EXISTS {$database}");
            $this->info("Created database: {$database}");
            
            // Create user and grant privileges
            $password = env('DB_PASSWORD', '');
            
            if ($user === 'reports_readonly') {
                // Read-only user for reports database
                DB::statement("CREATE USER IF NOT EXISTS '{$user}'@'localhost' IDENTIFIED BY '{$password}'");
                DB::statement("GRANT SELECT ON {$database}.* TO '{$user}'@'localhost'");
            } else {
                // Full access users for other databases
                DB::statement("CREATE USER IF NOT EXISTS '{$user}'@'localhost' IDENTIFIED BY '{$password}'");
                DB::statement("GRANT ALL PRIVILEGES ON {$database}.* TO '{$user}'@'localhost'");
            }
            
            DB::statement("FLUSH PRIVILEGES");
            $this->info("Created user: {$user} with appropriate privileges");
            
        } catch (\Exception $e) {
            $this->error("Failed to create {$database}: " . $e->getMessage());
        }
    }
}