<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('objects', function (Blueprint $t) {
            $t->unsignedBigInteger('created_sequence')->default(0);
            $t->unsignedBigInteger('updated_sequence')->default(0);
            $t->index(['group_id', 'thread_id', 'created_sequence']);
        });
        // Preserve pre-existing objects; only public committed transport order is materialized.
        DB::statement('UPDATE objects o JOIN (SELECT object_id, MIN(sequence) AS first_seq, MAX(sequence) AS last_seq FROM sync_events WHERE object_id IS NOT NULL GROUP BY object_id) e ON e.object_id=o.id SET o.created_sequence=e.first_seq, o.updated_sequence=e.last_seq');
    }

    public function down(): void
    {
        Schema::table('objects', function (Blueprint $t) {
            $t->dropIndex(['group_id', 'thread_id', 'created_sequence']);
            $t->dropColumn(['created_sequence', 'updated_sequence']);
        });
    }
};
