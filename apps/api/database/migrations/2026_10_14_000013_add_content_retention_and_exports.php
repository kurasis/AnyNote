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
            $t->enum('payload_status', ['retained', 'pruned'])->default('retained');
            $t->timestamp('payload_pruned_at')->nullable();
        });
        DB::statement('ALTER TABLE object_revisions MODIFY ciphertext MEDIUMBLOB NULL');
        DB::statement('ALTER TABLE object_key_wraps MODIFY wrap_record BLOB NULL');
        // Only the one-way payload compaction transition is mutable. All signed
        // ancestry, author/context metadata and deletes keep their original guards.
        DB::unprepared('DROP TRIGGER immutable_object_revisions_update');
        DB::unprepared("CREATE TRIGGER immutable_object_revisions_update BEFORE UPDATE ON object_revisions FOR EACH ROW BEGIN IF NOT (OLD.payload_status = 'retained' AND NEW.payload_status = 'pruned' AND NEW.ciphertext IS NULL AND NEW.ciphertext_bytes = 0 AND NEW.payload_pruned_at IS NOT NULL AND NEW.revision_id = OLD.revision_id AND NEW.object_id = OLD.object_id AND NEW.group_id = OLD.group_id AND NEW.author_account_id = OLD.author_account_id AND NEW.author_device_id = OLD.author_device_id AND NEW.operation_id = OLD.operation_id AND NEW.epoch_number = OLD.epoch_number AND NEW.payload_schema = OLD.payload_schema AND NEW.envelope_digest = OLD.envelope_digest AND NEW.signed_envelope = OLD.signed_envelope AND NEW.committed_at = OLD.committed_at) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable record'; END IF; END");
        DB::unprepared('DROP TRIGGER immutable_object_key_wraps_update');
        DB::unprepared("CREATE TRIGGER immutable_object_key_wraps_update BEFORE UPDATE ON object_key_wraps FOR EACH ROW BEGIN IF NOT (OLD.wrap_record IS NOT NULL AND NEW.wrap_record IS NULL AND NEW.ciphertext_bytes = 0 AND NEW.revision_id = OLD.revision_id AND EXISTS (SELECT 1 FROM object_revisions WHERE revision_id = OLD.revision_id AND payload_status = 'pruned')) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable record'; END IF; END");
        Schema::table('objects', fn (Blueprint $t) => $t->timestamp('trash_expires_at')->nullable());
        Schema::table('snapshot_sessions', function (Blueprint $t) {
            $t->binary('export_selection')->nullable();
            $t->unsignedBigInteger('served_bytes')->default(0);
            $t->unsignedBigInteger('renewed_bytes')->default(0);
            $t->timestamp('maximum_expires_at')->nullable();
        });
        DB::statement('ALTER TABLE snapshot_sessions MODIFY export_selection MEDIUMBLOB NULL');
        Schema::create('snapshot_progress', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('snapshot_id', 22);
            $t->string('kind', 16);
            $t->char('reference_id', 22);
            $t->unsignedInteger('part_index');
            $t->unsignedBigInteger('bytes');
            $t->primary(['snapshot_id', 'kind', 'reference_id', 'part_index']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
        });
        Schema::create('export_snapshot_items', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('snapshot_id', 22);
            $t->unsignedInteger('item_index');
            $t->char('group_id', 22);
            $t->string('object_kind', 24);
            $t->char('revision_id', 22);
            $t->binary('item_record');
            $t->primary(['snapshot_id', 'item_index']);
            $t->unique(['snapshot_id', 'object_kind', 'revision_id']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
        });
        Schema::create('export_snapshot_pages', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('snapshot_id', 22);
            $t->unsignedInteger('page_index');
            $t->binary('page_record');
            $t->primary(['snapshot_id', 'page_index']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
        });
        DB::statement('ALTER TABLE export_snapshot_items MODIFY item_record MEDIUMBLOB NOT NULL');
        DB::statement('ALTER TABLE export_snapshot_pages MODIFY page_record MEDIUMBLOB NOT NULL');
        Schema::create('content_retention_pins', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('id', 22)->primary();
            $t->char('account_id', 22);
            $t->char('group_id', 22);
            $t->char('revision_id', 22);
            $t->timestamp('created_at')->useCurrent();
            $t->unique(['account_id', 'revision_id']);
            $t->foreign('revision_id')->references('revision_id')->on('object_revisions')->restrictOnDelete();
        });
        Schema::create('derived_preview_links', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('group_id', 22);
            $t->char('source_version_id', 22);
            $t->char('derived_version_id', 22);
            $t->char('operation_id', 22);
            $t->char('account_id', 22);
            $t->char('device_id', 22);
            $t->char('request_digest', 43);
            $t->binary('signed_record');
            $t->timestamp('created_at')->useCurrent();
            $t->primary(['source_version_id', 'derived_version_id']);
            $t->unique(['account_id', 'device_id', 'operation_id']);
            $t->foreign('source_version_id')->references('id')->on('file_versions')->restrictOnDelete();
            $t->foreign('derived_version_id')->references('id')->on('file_versions')->restrictOnDelete();
        });
    }

    public function down(): void
    {
        if (DB::table('object_revisions')->where('payload_status', 'pruned')->exists() || DB::table('snapshot_sessions')->where('state', 'active')->where('purpose', 'export')->exists()) {
            throw new RuntimeException('Retained proof and active exports require a compatible client; downgrade is not automatic');
        }
        foreach (['derived_preview_links', 'content_retention_pins', 'snapshot_progress', 'export_snapshot_items', 'export_snapshot_pages'] as $table) {
            Schema::dropIfExists($table);
        }
        foreach (['object_revisions', 'object_key_wraps'] as $table) {
            DB::unprepared('DROP TRIGGER immutable_'.$table.'_update');
            DB::unprepared('CREATE TRIGGER immutable_'.$table.'_update BEFORE UPDATE ON '.$table." FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable record'");
        }
        Schema::table('snapshot_sessions', fn (Blueprint $t) => $t->dropColumn(['export_selection', 'served_bytes', 'renewed_bytes', 'maximum_expires_at']));
        Schema::table('objects', fn (Blueprint $t) => $t->dropColumn('trash_expires_at'));
        Schema::table('object_revisions', fn (Blueprint $t) => $t->dropColumn(['payload_status', 'payload_pruned_at']));
        DB::statement('ALTER TABLE object_revisions MODIFY ciphertext MEDIUMBLOB NOT NULL');
        DB::statement('ALTER TABLE object_key_wraps MODIFY wrap_record BLOB NOT NULL');
    }
};
