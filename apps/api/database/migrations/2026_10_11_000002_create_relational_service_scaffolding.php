<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('passkey_credentials', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $t->string('credential_digest', 64)->unique();
            $t->binary('public_key');
            $t->unsignedBigInteger('counter')->default(0);
            $t->binary('flags');
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('auth_recovery_codes', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $t->char('code_hash', 64)->unique();
            $t->timestamp('consumed_at')->nullable();
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('refresh_tokens', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $id('device_id');
            $id('family_id');
            $t->char('secret_hash', 64)->unique();
            $t->enum('state', ['active', 'used', 'revoked']);
            $t->timestamp('expires_at');
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('account_roster_events', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $t->unsignedBigInteger('sequence');
            $t->char('parent_digest', 43)->nullable();
            $t->char('digest', 43)->unique();
            $t->binary('signed_record');
            $t->unique(['account_id', 'sequence']);
            $t->foreign('account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        Schema::create('enrollment_sessions', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $t->char('commitment', 43);
            $t->enum('state', ['pending', 'approved', 'confirmed', 'expired', 'cancelled']);
            $t->binary('relay_ciphertext')->nullable();
            $t->timestamp('expires_at');
            $t->index(['state', 'expires_at']);
            $t->foreign('account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        Schema::create('group_policy_events', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->unsignedBigInteger('sequence');
            $t->char('parent_digest', 43)->nullable();
            $t->char('digest', 43)->unique();
            $t->binary('signed_record');
            $t->unique(['group_id', 'sequence']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('group_key_epochs', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->unsignedBigInteger('epoch_number');
            $t->char('policy_digest', 43);
            $t->char('digest', 43)->unique();
            $t->binary('signed_transition');
            $t->unique(['group_id', 'epoch_number']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('key_envelopes', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->unsignedBigInteger('epoch_number');
            $id('recipient_account_id');
            $t->enum('recipient_kind', ['device', 'account-recovery']);
            $t->char('recipient_key_fingerprint', 43);
            $t->binary('signed_record');
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->index(['recipient_key_fingerprint', 'group_id', 'epoch_number'], 'envelopes_recipient_epoch');
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
            $t->foreign('recipient_account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        Schema::create('membership_invites', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->char('target_root', 43);
            $t->enum('role', ['editor', 'reader']);
            $t->binary('signed_intent');
            $t->binary('signed_acceptance')->nullable();
            $t->enum('state', ['pending', 'accepted', 'activated', 'declined', 'expired']);
            $t->timestamp('expires_at');
            $t->index(['state', 'expires_at']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('security_transition_staging', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->char('pending_group_id', 22)->nullable()->unique();
            $t->char('expected_policy_digest', 43);
            $t->binary('expected_rosters');
            $t->binary('signed_descriptor');
            $t->enum('state', ['staged', 'committed', 'cancelled', 'expired']);
            $t->timestamp('expires_at');
            $t->index(['state', 'expires_at']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('security_transition_pages', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('transition_id');
            $t->unsignedBigInteger('page_index');
            $t->char('digest', 43);
            $t->binary('page_record');
            $t->unique(['transition_id', 'page_index']);
            $t->foreign('transition_id')->references('id')->on('security_transition_staging')->restrictOnDelete();
        });
        Schema::create('file_objects', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('group_id');
            $t->char('current_version_id', 22)->nullable();
            $t->boolean('tombstoned')->default(false);
            $t->unique(['group_id', 'id']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('file_versions', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('file_id');
            $id('group_id');
            $id('uploader_account_id');
            $t->char('manifest_revision_id', 22)->nullable();
            $t->char('manifest_digest', 43);
            $t->enum('state', ['staged', 'committed', 'reclaimable', 'deleted']);
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->unique(['group_id', 'id']);
            $t->index(['group_id', 'file_id']);
            $t->foreign('file_id')->references('id')->on('file_objects')->restrictOnDelete();
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
            $t->foreign('uploader_account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('file_chunks', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('file_version_id');
            $t->unsignedBigInteger('chunk_index');
            $id('blob_id');
            $t->char('digest', 43);
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->unique(['file_version_id', 'chunk_index']);
            $t->foreign('file_version_id')->references('id')->on('file_versions')->restrictOnDelete();
        });
        Schema::create('upload_sessions', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $id('device_id');
            $id('group_id');
            $id('file_version_id');
            $id('reservation_id');
            $t->enum('state', ['reserved', 'receiving', 'ready', 'committed', 'cancelled', 'expired']);
            $t->timestamp('expires_at');
            $t->index(['state', 'expires_at']);
            $t->foreign('reservation_id')->references('id')->on('quota_reservations')->restrictOnDelete();
            $t->foreign('file_version_id')->references('id')->on('file_versions')->restrictOnDelete();
        });
        Schema::create('upload_parts', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('upload_id');
            $t->unsignedBigInteger('chunk_index');
            $id('blob_id');
            $t->char('digest', 43);
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->unique(['upload_id', 'chunk_index']);
            $t->foreign('upload_id')->references('id')->on('upload_sessions')->restrictOnDelete();
        });
        Schema::create('snapshot_sessions', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $id('device_id');
            $t->enum('purpose', ['resync', 'export']);
            $id('transport_generation');
            $t->unsignedBigInteger('watermark');
            $t->timestamp('created_at')->useCurrent();
            $t->timestamp('expires_at');
            $t->enum('state', ['active', 'cancelled', 'expired']);
            $t->index(['state', 'expires_at']);
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('snapshot_items', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('snapshot_id');
            $id('group_id');
            $id('revision_id');
            $t->unsignedBigInteger('item_index');
            $t->binary('inventory_record');
            $t->unique(['snapshot_id', 'item_index']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
            $t->foreign('revision_id')->references('revision_id')->on('object_revisions')->restrictOnDelete();
        });
        Schema::create('reference_pins', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('snapshot_id');
            $id('group_id');
            $id('revision_id');
            $t->unique(['snapshot_id', 'revision_id']);
            $t->foreign('snapshot_id')->references('id')->on('snapshot_sessions')->restrictOnDelete();
            $t->foreign('revision_id')->references('revision_id')->on('object_revisions')->restrictOnDelete();
        });
        Schema::create('publication_journal', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $id('device_id');
            $id('file_version_id');
            $id('operation_id');
            $t->enum('state', ['unattached', 'referenced', 'cancelled']);
            $t->unique(['account_id', 'device_id', 'operation_id', 'file_version_id'], 'publication_operation_file');
            $t->foreign('file_version_id')->references('id')->on('file_versions')->restrictOnDelete();
        });
        Schema::create('security_events', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $t->char('actor_account_id', 22)->nullable();
            $t->string('action', 32);
            $t->enum('outcome', ['accepted', 'rejected']);
            $t->timestamp('occurred_at')->useCurrent();
            $t->index(['actor_account_id', 'occurred_at']);
        });
        Schema::create('notification_subscriptions', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $id('account_id');
            $id('device_id');
            $t->binary('protected_endpoint');
            $t->binary('protected_push_material');
            $t->enum('status', ['active', 'revoked']);
            $t->index(['account_id', 'device_id', 'status'], 'subscription_actor_status');
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('gc_coordination', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $t->unsignedTinyInteger('singleton')->unique();
        });
        Schema::create('operator_coordination', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $id = static fn (string $name) => $t->char($name, 22);
            $id('id');
            $t->primary('id');
            $t->unsignedTinyInteger('singleton')->unique();
        });
        Schema::create('attachment_refs', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('revision_id', 22);
            $t->char('file_version_id', 22);
            $t->char('group_id', 22);
            $t->primary(['revision_id', 'file_version_id']);
            $t->foreign(['group_id', 'file_version_id'])->references(['group_id', 'id'])->on('file_versions')->restrictOnDelete();
            $t->foreign('revision_id')->references('revision_id')->on('object_revisions')->restrictOnDelete();
        });
        DB::table('gc_coordination')->insert(['id' => 'AAAAAAAAAAAAAAAAAAAAAQ', 'singleton' => 1]);
        DB::table('operator_coordination')->insert(['id' => 'AAAAAAAAAAAAAAAAAAAAAQ', 'singleton' => 1]);
        foreach (['object_revisions', 'object_key_wraps', 'revision_parents', 'account_roster_events', 'group_policy_events', 'group_key_epochs', 'security_transition_pages'] as $table) {
            foreach (['UPDATE', 'DELETE'] as $action) {
                DB::unprepared('CREATE TRIGGER immutable_'.$table.'_'.strtolower($action).' BEFORE '.$action.' ON '.$table." FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable record'");
            }
        }
    }

    public function down(): void
    {
        foreach (['attachment_refs', 'operator_coordination', 'gc_coordination', 'notification_subscriptions', 'security_events', 'publication_journal', 'reference_pins', 'snapshot_items', 'snapshot_sessions', 'upload_parts', 'upload_sessions', 'file_chunks', 'file_versions', 'file_objects', 'security_transition_pages', 'security_transition_staging', 'membership_invites', 'key_envelopes', 'group_key_epochs', 'group_policy_events', 'enrollment_sessions', 'account_roster_events', 'refresh_tokens', 'auth_recovery_codes', 'passkey_credentials'] as $table) {
            Schema::dropIfExists($table);
        }
    }
};
