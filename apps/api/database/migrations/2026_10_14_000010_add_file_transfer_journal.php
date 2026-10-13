<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('upload_sessions', function (Blueprint $t) {
            $t->longText('context_record')->nullable();
            $t->char('request_digest', 43)->nullable();
            $t->unsignedBigInteger('plaintext_bytes')->nullable();
            $t->timestamp('created_at')->nullable();
            $t->timestamp('progress_at')->nullable();
            $t->longText('receipt_record')->nullable();
        });
        Schema::table('file_versions', function (Blueprint $t) {
            $t->longText('manifest_record')->nullable();
            $t->timestamp('committed_at')->nullable();
            $t->timestamp('unattached_expires_at')->nullable();
        });
        Schema::create('snapshot_file_pins', function (Blueprint $t) {
            $t->char('snapshot_id', 22)->collation('ascii_bin');
            $t->char('file_version_id', 22)->collation('ascii_bin');
            $t->primary(['snapshot_id', 'file_version_id']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
            $t->foreign('file_version_id')->references('id')->on('file_versions')->restrictOnDelete();
        });
    }

    public function down(): void
    {
        // Rollback must not discard durable encrypted upload/recovery work.
        throw new LogicException('Explicit file-journal migration required');
    }
};
