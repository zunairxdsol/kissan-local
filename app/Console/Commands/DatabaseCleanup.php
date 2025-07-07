<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\LoggingService;
use Illuminate\Support\Facades\DB;

class DatabaseCleanup extends Command
{
    protected $signature = 'db:cleanup {--days=30} {--confirm}';
    protected $description = 'Clean up old logs and expired data';

    public function handle()
    {
        $days = (int) $this->option('days');
        $confirm = $this->option('confirm');
        
        if (!$confirm && !$this->confirm("This will delete logs older than {$days} days. Continue?")) {
            $this->info('Cleanup cancelled.');
            return 0;
        }
        
        $this->info("Starting cleanup of data older than {$days} days...");
        
        try {
            // Clean up logs
            $loggingService = app(LoggingService::class);
            $loggingService->cleanupOldLogs($days);
            
            // Clean up expired tokens
            $expiredTokens = DB::connection('activity_logs')
                ->table('activity_logs')
                ->whereNotNull('auth_token')
                ->where('expires_at', '<', now())
                ->count();
                
            if ($expiredTokens > 0) {
                DB::connection('activity_logs')
                    ->table('activity_logs')
                    ->whereNotNull('auth_token')
                    ->where('expires_at', '<', now())
                    ->delete();
                    
                $this->info("Cleaned up {$expiredTokens} expired tokens");
            }
            
            $this->info('Database cleanup completed successfully!');
            
        } catch (\Exception $e) {
            $this->error('Cleanup failed: ' . $e->getMessage());
            return 1;
        }
        
        return 0;
    }
}
