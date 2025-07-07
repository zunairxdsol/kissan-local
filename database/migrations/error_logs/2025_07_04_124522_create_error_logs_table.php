<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected $connection = 'error_logs';

    public function up()
    {
        Schema::connection('error_logs')->create('error_logs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('error_type')->index();
            $table->text('message');
            $table->longText('stack_trace')->nullable();
            $table->json('request_data')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('url')->nullable();
            $table->string('method', 10)->nullable();
            $table->integer('status_code')->nullable();
            $table->string('file')->nullable();
            $table->integer('line')->nullable();
            $table->json('context')->nullable();
            $table->timestamp('created_at')->useCurrent();
            
           
        });
    }

    public function down()
    {
        Schema::connection('error_logs')->dropIfExists('error_logs');
    }
};
