<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * Define the application's command schedule.
     */
     protected $commands = [
        Commands\TestDatabaseConnections::class,
        Commands\SetupDatabases::class,
        Commands\MigrateMultiDatabase::class,
        Commands\CreateMigrationMulti::class,
        Commands\SyncReportsDatabase::class,
        Commands\MigrationStatus::class,
        Commands\DatabaseCleanup::class,
    ];
    protected function schedule(Schedule $schedule)
    {
        // Sync reports database every hour
        $schedule->command('sync:reports')->hourly()->withoutOverlapping();
        
        // Clean up old logs daily at 2 AM
        $schedule->command('db:cleanup --confirm')->dailyAt('02:00');
        
        // Full reports sync weekly (Sunday at 3 AM)
        $schedule->command('sync:reports --full --force')->weekly()->sundays()->at('03:00');
        
        // Test database connections daily
        $schedule->command('db:test-connections')->dailyAt('01:00');
    }

    /**
     * Register the commands for the application.
     */
    protected function commands(): void
    {
        $this->load(__DIR__.'/Commands');

        require base_path('routes/console.php');
    }
}
