<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected $connection = 'reports_logs';

    public function up()
    {
        Schema::connection('reports_logs')->create('reports_data', function (Blueprint $table) {
            $table->id();
            $table->string('type'); // 'user', 'product', 'category', 'role'
            $table->string('name');
            $table->string('email')->nullable();
            $table->string('slug')->nullable();
            $table->text('description')->nullable();
            $table->text('short_description')->nullable();
            
            // Product specific fields
            $table->decimal('price', 10, 2)->nullable();
            $table->decimal('sale_price', 10, 2)->nullable();
            $table->string('sku')->nullable();
            $table->integer('stock_quantity')->nullable();
            $table->boolean('manage_stock')->nullable();
            $table->decimal('weight', 8, 2)->nullable();
            $table->json('dimensions')->nullable();
            $table->json('images')->nullable();
            $table->json('attributes')->nullable();
            
            // User specific fields
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamp('last_login_at')->nullable();
            $table->string('avatar')->nullable();
            $table->json('preferences')->nullable();
            $table->json('permissions')->nullable();
            
            // Category specific fields
            $table->string('image')->nullable();
            $table->integer('sort_order')->nullable();
            $table->integer('products_count')->nullable();
            
            // Role specific fields
            $table->json('permissions_json')->nullable();
            $table->json('permissions_list')->nullable();
            $table->integer('users_count')->nullable();
            
            // Relationship fields
            $table->unsignedBigInteger('role_id')->nullable();
            $table->string('role_name')->nullable();
            $table->unsignedBigInteger('category_id')->nullable();
            $table->string('category_name')->nullable();
            $table->string('category_slug')->nullable();
            $table->unsignedBigInteger('created_by')->nullable();
            $table->string('creator_name')->nullable();
            $table->string('creator_email')->nullable();
            
            // Common fields
            $table->string('status')->default('active');
            $table->boolean('is_active')->default(true);
            $table->timestamp('created_at')->nullable();
            $table->timestamp('updated_at')->nullable();
            $table->timestamp('deleted_at')->nullable();
            $table->timestamp('synced_at')->useCurrent();
            
            // Essential indexes (from original migrations)
            $table->index('type'); // Critical for entity type queries
            $table->index('email'); // User lookups
            $table->index('slug'); // Product/category lookups
            $table->index('sku'); // Product lookups
            $table->index('status'); // Status filtering
            $table->index('is_active'); // Active/inactive filtering
            $table->index('role_id'); // User role relationships
            $table->index('category_id'); // Product category relationships
            $table->index('created_by'); // Product creator relationships
            $table->index('synced_at'); // Sync operations
            $table->index('deleted_at'); // Soft delete queries
            
            // Composite indexes for common query patterns
            $table->index(['type', 'status']); // Filter by type and status
            $table->index(['type', 'is_active']); // Filter by type and active status
            $table->index(['status', 'category_id']); // Product queries by status and category
            
            // Optional indexes - comment out if not needed
            // $table->index('name'); // Only if you search by name frequently
            // $table->index('price'); // Only if you filter/sort by price often
            // $table->index('sort_order'); // Only if you sort categories frequently
            // $table->index('last_login_at'); // Only if you query recent logins often
        });
    }

    public function down()
    {
        Schema::connection('reports_logs')->dropIfExists('reports_data');
    }
};