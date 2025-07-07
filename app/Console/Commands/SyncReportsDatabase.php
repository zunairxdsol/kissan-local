<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\ReportsSyncService;

class SyncReportsDatabase extends Command
{
    protected $signature = 'sync:reports {--table=} {--full} {--force}';
    protected $description = 'Sync data from main database to reports database';

    protected $syncService;

    public function __construct(ReportsSyncService $syncService)
    {
        parent::__construct();
        $this->syncService = $syncService;
    }

    public function handle()
    {
        $table = $this->option('table');
        $full = $this->option('full');
        $force = $this->option('force');
        
        try {
            if ($full) {
                $this->info('Starting full database sync...');
                
                if (!$force && !$this->confirm('This will overwrite all data in reports database. Continue?')) {
                    $this->info('Sync cancelled.');
                    return 0;
                }
                
                $this->syncService->fullSync();
                $this->info('Full sync completed successfully!');
                
            } elseif ($table) {
                $validTables = ['users', 'products', 'categories', 'roles'];
                
                if (!in_array($table, $validTables)) {
                    $this->error("Invalid table. Valid options: " . implode(', ', $validTables));
                    return 1;
                }
                
                $this->info("Syncing table: {$table}");
                $this->syncService->syncTable($table);
                $this->info("Table {$table} synced successfully!");
                
            } else {
                $this->info('Starting incremental sync...');
                $this->syncService->incrementalSync();
                $this->info('Incremental sync completed successfully!');
            }
            
            return 0;
            
        } catch (\Exception $e) {
            $this->error('Sync failed: ' . $e->getMessage());
            return 1;
        }
    }
}