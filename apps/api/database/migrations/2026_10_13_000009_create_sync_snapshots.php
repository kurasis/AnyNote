<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('sync_counters', function (Blueprint $t) {
            $t->unsignedBigInteger('retained_from')->default(0);
        });
        Schema::table('snapshot_sessions', function (Blueprint $t) {
            $t->char('session_id', 22)->nullable();
            $t->char('root_fingerprint', 43)->nullable();
            $t->char('operation_id', 22)->nullable();
            $t->char('scope_group_id', 22)->nullable();
            $t->char('request_digest', 43)->nullable();
            $t->binary('descriptor')->nullable();
            $t->char('catalog_digest', 43)->nullable();
            $t->unsignedBigInteger('catalog_count')->default(0);
            $t->unique(['account_id', 'device_id', 'operation_id']);
        });
        DB::statement('ALTER TABLE snapshot_sessions MODIFY descriptor MEDIUMBLOB NULL');
        DB::statement('ALTER TABLE snapshot_items MODIFY inventory_record MEDIUMBLOB NOT NULL');
        Schema::create('snapshot_pages', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('snapshot_id', 22);
            $t->unsignedInteger('page_index');
            $t->binary('page_record');
            $t->primary(['snapshot_id', 'page_index']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
        });
        DB::statement('ALTER TABLE snapshot_pages MODIFY page_record MEDIUMBLOB NOT NULL');
        Schema::create('snapshot_catalog', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('snapshot_id', 22);
            $t->char('group_id', 22);
            $t->unsignedInteger('item_index');
            $t->binary('status_record');
            $t->primary(['snapshot_id', 'item_index']);
            $t->unique(['snapshot_id', 'group_id']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
        });
        DB::statement('ALTER TABLE snapshot_catalog MODIFY status_record MEDIUMBLOB NOT NULL');
        Schema::create('sync_acknowledgements', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('account_id', 22);
            $t->char('device_id', 22);
            $t->char('scope_id', 22);
            $t->char('generation', 22);
            $t->unsignedBigInteger('sequence');
            $t->primary(['account_id', 'device_id', 'scope_id']);
        });
    }

    public function down(): void
    {
        // Retained snapshot pins are not automatically dropped by a production downgrade.
        if (DB::table('snapshot_sessions')->where('state', 'active')->exists()) {
            throw new RuntimeException('Cancel active snapshots before schema downgrade');
        }
        Schema::dropIfExists('sync_acknowledgements');
        Schema::dropIfExists('snapshot_catalog');
        Schema::dropIfExists('snapshot_pages');
        Schema::table('snapshot_sessions', function (Blueprint $t) {
            $t->dropUnique(['account_id', 'device_id', 'operation_id']);
            $t->dropColumn(['session_id', 'root_fingerprint', 'operation_id', 'scope_group_id', 'request_digest', 'descriptor', 'catalog_digest', 'catalog_count']);
        });
        Schema::table('sync_counters', fn (Blueprint $t) => $t->dropColumn('retained_from'));
    }
};
