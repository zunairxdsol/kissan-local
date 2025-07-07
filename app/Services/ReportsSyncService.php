<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class ReportsSyncService
{
    public function fullSync()
    {
        Log::info('Full sync started - implementation coming in next phase');
        // Implementation will be added in the next phase with models
    }
    
    public function incrementalSync()
    {
        Log::info('Incremental sync started - implementation coming in next phase');
        // Implementation will be added in the next phase with models
    }
    
    public function syncTable($table)
    {
        Log::info("Table sync started for {$table} - implementation coming in next phase");
        // Implementation will be added in the next phase with models
    }
}