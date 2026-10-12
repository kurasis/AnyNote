<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('account_identities', function (Blueprint $t) {
            $t->unsignedTinyInteger('device_limit')->default(5);
        });
        Schema::table('sync_events', function (Blueprint $t) {
            $t->char('group_id', 22)->nullable()->change();
        });
        Schema::table('devices', function (Blueprint $t) {
            $t->char('parent_device_id', 22)->nullable()->index();
            $t->enum('platform', ['windows', 'pwa', 'unknown'])->default('unknown');
            $t->timestamp('enrolled_at')->useCurrent();
        });
        Schema::table('enrollment_sessions', function (Blueprint $t) {
            $t->char('creator_session_id', 22);
            $t->char('new_session_id', 22)->nullable();
            $t->char('approver_device_id', 22)->nullable();
            $t->char('new_device_id', 22)->nullable();
            $t->enum('mode', ['new-device-offer', 'existing-device-invitation']);
            $t->text('public_record');
            $t->text('offer_record')->nullable();
            $t->text('transcript_record')->nullable();
            $t->text('approval_record')->nullable();
            $t->text('event_record')->nullable();
        });
        Schema::create('device_relay_frames', function (Blueprint $t) {
            $t->engine = 'InnoDB'; $t->charset = 'ascii'; $t->collation = 'ascii_bin';
            $t->char('enrollment_id', 22);
            $t->string('message', 32);
            $t->text('frame');
            $t->primary(['enrollment_id', 'message']);
            $t->foreign('enrollment_id')->references('id')->on('enrollment_sessions')->restrictOnDelete();
        });
        Schema::create('device_transition_receipts', function (Blueprint $t) {
            $t->engine = 'InnoDB'; $t->charset = 'ascii'; $t->collation = 'ascii_bin';
            $t->char('operation_id', 22)->primary();
            $t->char('account_id', 22)->index();
            $t->char('session_id', 22);
            $t->char('request_digest', 43);
            $t->text('result');
            $t->timestamp('expires_at');
        });
        Schema::create('account_security_notifications', function (Blueprint $t) {
            $t->engine = 'InnoDB'; $t->charset = 'ascii'; $t->collation = 'ascii_bin';
            $t->char('id', 22)->primary();
            $t->char('account_id', 22)->index();
            $t->enum('kind', ['device-enrolled', 'device-revoked', 'recovery-reset', 'passkey-added']);
            $t->timestamp('created_at')->useCurrent();
        });
        Schema::create('account_settings_genesis', function (Blueprint $t) {
            $t->engine = 'InnoDB'; $t->charset = 'ascii'; $t->collation = 'ascii_bin';
            $t->char('account_id', 22)->primary();
            $t->char('group_id', 22)->unique();
            $t->char('request_digest', 43);
            $t->mediumText('commit_record');
            $t->mediumText('grant_page');
        });
    }

    public function down(): void
    {
        throw new LogicException('No destructive downgrade: preserve device records, receipts and encrypted settings');
    }
};
