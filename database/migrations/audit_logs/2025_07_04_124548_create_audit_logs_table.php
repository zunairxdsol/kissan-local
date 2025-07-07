<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected $connection = 'audit_logs';

    public function up()
    {
        Schema::connection('audit_logs')->create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('table_name')->index();
            $table->unsignedBigInteger('record_id')->index();
            $table->string('action')->index(); // create, update, delete, restore
            $table->json('old_values')->nullable();
            $table->json('new_values')->nullable();
            $table->json('changed_fields')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('reason')->nullable();
            $table->timestamp('created_at')->useCurrent();
            
           
        });
    }

    public function down()
    {
        Schema::connection('audit_logs')->dropIfExists('audit_logs');
    }
};
