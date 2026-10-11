<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('object_revisions', function (Blueprint $t) {
            $t->unique(['group_id', 'revision_id'], 'revision_group_identity');
        });
        Schema::table('attachment_refs', function (Blueprint $t) {
            $t->foreign(['group_id', 'revision_id'], 'attachment_revision_group')->references(['group_id', 'revision_id'])->on('object_revisions')->restrictOnDelete();
        });
        Schema::table('file_versions', function (Blueprint $t) {
            $t->foreign(['group_id', 'file_id'], 'file_version_group_identity')->references(['group_id', 'id'])->on('file_objects')->restrictOnDelete();
        });
        foreach (['snapshot_items', 'reference_pins'] as $table) {
            Schema::table($table, function (Blueprint $t) use ($table) {
                $t->foreign(['group_id', 'revision_id'], $table.'_revision_group')->references(['group_id', 'revision_id'])->on('object_revisions')->restrictOnDelete();
            });
        }
        foreach (DB::select("SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND DATA_TYPE='bigint' AND COLUMN_TYPE LIKE '%unsigned' AND EXTRA NOT LIKE '%auto_increment%'") as $column) {
            $name = 'u63_'.substr(hash('sha256', $column->TABLE_NAME.'/'.$column->COLUMN_NAME), 0, 16);
            DB::statement('ALTER TABLE `'.$column->TABLE_NAME.'` ADD CONSTRAINT '.$name.' CHECK (`'.$column->COLUMN_NAME.'` <= 9223372036854775807)');
        }
        DB::statement('ALTER TABLE quota_ledgers ADD CONSTRAINT bounded_quota CHECK (limit_bytes <= 100000000000 AND pending_limit_bytes <= 5368709120 AND committed_bytes <= limit_bytes AND reserved_bytes <= pending_limit_bytes AND reserved_bytes <= limit_bytes AND committed_bytes <= limit_bytes - reserved_bytes)');
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE quota_ledgers DROP CONSTRAINT bounded_quota');
        foreach (DB::select("SELECT TABLE_NAME, CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_TYPE='CHECK' AND CONSTRAINT_NAME LIKE 'u63_%'") as $constraint) {
            DB::statement('ALTER TABLE `'.$constraint->TABLE_NAME.'` DROP CONSTRAINT '.$constraint->CONSTRAINT_NAME);
        }
        foreach (['snapshot_items', 'reference_pins'] as $table) {
            Schema::table($table, fn (Blueprint $t) => $t->dropForeign($table.'_revision_group'));
        }
        Schema::table('file_versions', fn (Blueprint $t) => $t->dropForeign('file_version_group_identity'));
        Schema::table('attachment_refs', fn (Blueprint $t) => $t->dropForeign('attachment_revision_group'));
        Schema::table('object_revisions', fn (Blueprint $t) => $t->dropUnique('revision_group_identity'));
    }
};
