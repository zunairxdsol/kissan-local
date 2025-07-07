<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

class MigrateMultiDatabase extends Command
{
    protected $signature = 'migrate:multi {--fresh} {--seed} {--force}';
    protected $description = 'Run migrations for all databases';

    public function handle()
    {
        $databases = [
            'main' => 'database/migrations/main',
            'error_logs' => 'database/migrations/error_logs',
            'activity_logs' => 'database/migrations/activity_logs',
            'audit_logs' => 'database/migrations/audit_logs',
            'reports_logs' => 'database/migrations/reports_logs'
        ];
        
        $this->info('Running migrations for all databases...');
        $this->newLine();
        
        foreach ($databases as $database => $migrationPath) {
            $this->info("Migrating database: {$database}");
            
            // Check if migration path exists
            if (!File::exists(base_path($migrationPath))) {
                $this->warn("Migration path does not exist: {$migrationPath}");
                $this->warn("Creating directory: {$migrationPath}");
                File::makeDirectory(base_path($migrationPath), 0755, true);
            }
            
            $command = 'migrate';
            $options = [
                '--database' => $database,
                '--path' => $migrationPath,
            ];
            
            if ($this->option('force')) {
                $options['--force'] = true;
            }
            
            if ($this->option('fresh')) {
                $command = 'migrate:fresh';
            }
            
            try {
                Artisan::call($command, $options);
                $output = Artisan::output();
                
                if (strpos($output, 'Nothing to migrate') !== false) {
                    $this->line("<fg=yellow>⚠</> {$database}: Nothing to migrate");
                } else {
                    $this->line("<fg=green>✓</> {$database}: Migrated successfully");
                }
                
                // Seed only main database
                if ($this->option('seed') && $database === 'main') {
                    Artisan::call('db:seed', [
                        '--database' => $database,
                        '--force' => $this->option('force', false)
                    ]);
                    $this->line("<fg=green>✓</> {$database}: Seeded successfully");
                }
                
            } catch (\Exception $e) {
                $this->line("<fg=red>✗</> Failed to migrate {$database}: " . $e->getMessage());
            }
        }
        
        $this->newLine();
        $this->info('Migration process completed!');
        
        return 0;
    }
}
