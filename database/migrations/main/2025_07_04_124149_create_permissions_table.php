<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected $connection = 'main';

    public function up()
    {
        Schema::connection('main')->create('permissions', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('description')->nullable();
            $table->string('module')->nullable();
            $table->string('action')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
            
            $table->index(['module', 'action']);
            $table->index('is_active');
        });
    }

    public function down()
    {
        Schema::connection('main')->dropIfExists('permissions');
    }
};