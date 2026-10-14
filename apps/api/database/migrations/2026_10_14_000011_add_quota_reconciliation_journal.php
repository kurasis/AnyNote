<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('quota_reconciliation_baselines', function (Blueprint $t) {
            $t->string('scope', 128)->collation('ascii_bin')->primary();
            $t->unsignedBigInteger('committed_bytes');
            $t->unsignedBigInteger('reserved_bytes');
        });
        Schema::create('quota_movements', function (Blueprint $t) {
            $t->char('id', 22)->collation('ascii_bin')->primary();
            $t->string('scope', 128)->collation('ascii_bin')->index();
            $t->bigInteger('committed_delta');
            $t->bigInteger('reserved_delta');
            $t->timestamp('created_at')->useCurrent();
        });
        foreach (DB::table('quota_ledgers')->get() as $row) {
            DB::table('quota_reconciliation_baselines')->insert(['scope' => $row->scope, 'committed_bytes' => $row->committed_bytes, 'reserved_bytes' => $row->reserved_bytes]);
        }
    }

    public function down(): void
    {
        throw new LogicException('Explicit quota-journal migration required');
    }
};
