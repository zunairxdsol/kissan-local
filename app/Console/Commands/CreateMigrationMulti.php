<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

class CreateMigrationMulti extends Command
{
    protected $signature = 'make:migration-multi {name} {database} {--create=} {--table=}';
    protected $description = 'Create a migration for specific database';

    public function handle()
    {
        $name = $this->argument('name');
        $database = $this->argument('database');
        $create = $this->option('create');
        $table = $this->option('table');
        
        // Validate database
        $validDatabases = ['main', 'error_logs', 'activity_logs', 'audit_logs', 'reports_logs'];
        if (!in_array($database, $validDatabases)) {
            $this->error("Invalid database. Valid options: " . implode(', ', $validDatabases));
            return 1;
        }
        
        $timestamp = date('Y_m_d_His');
        $className = Str::studly($name);
        $filename = "{$timestamp}_{$name}.php";
        
        $path = base_path("database/migrations/{$database}");
        
        if (!File::exists($path)) {
            File::makeDirectory($path, 0755, true);
            $this->info("Created directory: {$path}");
        }
        
        $stub = $this->getStub($database, $className, $create, $table);
        
        File::put("{$path}/{$filename}", $stub);
        
        $this->info("Migration created: database/migrations/{$database}/{$filename}");
        
        return 0;
    }
    
    protected function getStub($database, $className, $create = null, $table = null)
    {
        if ($create) {
            return $this->getCreateStub($database, $className, $create);
        } elseif ($table) {
            return $this->getUpdateStub($database, $className, $table);
        } else {
            return $this->getBlankStub($database, $className);
        }
    }
    
    protected function getCreateStub($database, $className, $tableName)
    {
        return "<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected \$connection = '{$database}';

    public function up()
    {
        Schema::connection('{$database}')->create('{$tableName}', function (Blueprint \$table) {
            \$table->id();
            \$table->timestamps();
        });
    }

    public function down()
    {
        Schema::connection('{$database}')->dropIfExists('{$tableName}');
    }
};
";
    }
    
    protected function getUpdateStub($database, $className, $tableName)
    {
        return "<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected \$connection = '{$database}';

    public function up()
    {
        Schema::connection('{$database}')->table('{$tableName}', function (Blueprint \$table) {
            // Add your columns here
        });
    }

    public function down()
    {
        Schema::connection('{$database}')->table('{$tableName}', function (Blueprint \$table) {
            // Drop your columns here
        });
    }
};
";
    }
    
    protected function getBlankStub($database, $className)
    {
        return "<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected \$connection = '{$database}';

    public function up()
    {
        // Add your migration logic here
    }

    public function down()
    {
        // Add your rollback logic here
    }
};
";
    }
}