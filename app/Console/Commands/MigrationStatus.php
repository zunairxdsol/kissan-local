<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;

class MigrationStatus extends Command
{
    protected $signature = 'migrate:status-multi';
    protected $description = 'Show migration status for all databases';

    public function handle()
    {
        $databases = ['main', 'error_logs', 'activity_logs', 'audit_logs', 'reports_logs'];
        
        $this->info('Migration status for all databases:');
        $this->newLine();
        
        foreach ($databases as $database) {
            $this->info("Database: {$database}");
            $this->line(str_repeat('-', 50));
            
            try {
                Artisan::call('migrate:status', [
                    '--database' => $database,
                    '--path' => "database/migrations/{$database}"
                ]);
                
                $output = Artisan::output();
                $this->line($output);
                
            } catch (\Exception $e) {
                $this->error("Error checking {$database}: " . $e->getMessage());
            }
            
            $this->newLine();
        }
        
        return 0;
    }
}
