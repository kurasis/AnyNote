<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private function table(string $name, Closure $columns): void
    {
        Schema::create($name, function (Blueprint $t) use ($columns) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $columns($t);
        });
    }

    private function id(Blueprint $t, string $name = 'id'): void
    {
        $t->char($name, 22);
    }

    private function digest(Blueprint $t, string $name): void
    {
        $t->char($name, 43);
    }

    public function up(): void
    {
        $this->table('users', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $t->string('login_handle', 128)->unique();
            $t->enum('status', ['active', 'disabled', 'deleted']);
            $t->boolean('is_admin')->default(false);
            $t->timestamp('created_at')->useCurrent();
        });
        $this->table('account_identities', function (Blueprint $t) {
            $this->id($t, 'account_id');
            $t->primary('account_id');
            $this->digest($t, 'root_fingerprint');
            $t->unique('root_fingerprint');
            $t->binary('identity_record');
            $t->unsignedBigInteger('recovery_generation');
            $t->unsignedBigInteger('roster_sequence');
            $this->digest($t, 'roster_digest');
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        $this->table('devices', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'account_id');
            $this->digest($t, 'signing_key');
            $this->digest($t, 'encryption_key');
            $this->digest($t, 'certificate_digest');
            $t->binary('certificate_record');
            $t->unsignedBigInteger('recovery_generation');
            $t->enum('status', ['pending', 'active', 'revoked']);
            $t->boolean('can_sign_content')->default(false);
            $t->unique(['account_id', 'id']);
            $t->index(['account_id', 'status']);
            $t->foreign('account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        $this->table('auth_sessions', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'account_id');
            $this->id($t, 'device_id');
            $t->char('secret_hash', 64)->unique();
            $t->unsignedBigInteger('recovery_generation');
            $t->enum('state', ['restricted', 'trusted', 'revoked']);
            $t->timestamp('expires_at');
            $t->timestamp('authenticated_at');
            $t->index(['account_id', 'state', 'expires_at']);
            $t->foreign(['account_id', 'device_id'])->references(['account_id', 'id'])->on('devices')->restrictOnDelete();
        });
        $this->table('account_invites', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'creator_id');
            $t->char('token_hash', 64)->unique();
            $t->char('recipient_binding_hash', 64)->nullable();
            $t->enum('status', ['pending', 'consumed', 'cancelled']);
            $t->timestamp('expires_at');
            $t->index(['status', 'expires_at']);
            $t->foreign('creator_id')->references('id')->on('users')->restrictOnDelete();
        });
        $this->table('groups', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'owner_account_id');
            $t->enum('kind', ['private', 'shared']);
            $t->enum('state', ['active', 'archived', 'purged']);
            $t->unsignedBigInteger('policy_sequence');
            $this->digest($t, 'policy_digest');
            $t->unsignedBigInteger('epoch_number');
            $this->digest($t, 'epoch_digest');
            $t->char('history_checkpoint_digest', 43)->nullable();
            $t->boolean('rekey_required')->default(false);
            $t->boolean('history_closure_required')->default(false);
            $t->boolean('restore_quarantined')->default(false);
            $t->index('owner_account_id');
            $t->foreign('owner_account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        $this->table('group_memberships', function (Blueprint $t) {
            $this->id($t, 'group_id');
            $this->id($t, 'account_id');
            $t->primary(['group_id', 'account_id']);
            $t->enum('role', ['owner', 'editor', 'reader']);
            $t->enum('status', ['pending', 'active', 'removed']);
            $t->unsignedBigInteger('joined_policy');
            $t->unsignedBigInteger('removed_policy')->nullable();
            $t->index(['account_id', 'status', 'group_id']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
            $t->foreign('account_id')->references('account_id')->on('account_identities')->restrictOnDelete();
        });
        $this->table('objects', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'group_id');
            $t->enum('kind', ['group-metadata', 'thread', 'entry']);
            $t->char('thread_id', 22)->nullable();
            $t->boolean('archived')->default(false);
            $t->boolean('tombstoned')->default(false);
            $t->unique(['group_id', 'id']);
            $t->index(['group_id', 'thread_id']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
            $t->foreign(['group_id', 'thread_id'])->references(['group_id', 'id'])->on('objects')->restrictOnDelete();
        });
        $this->table('object_revisions', function (Blueprint $t) {
            $this->id($t, 'revision_id');
            $t->primary('revision_id');
            $this->id($t, 'object_id');
            $this->id($t, 'group_id');
            $this->id($t, 'author_account_id');
            $this->id($t, 'author_device_id');
            $this->id($t, 'operation_id');
            $t->unsignedBigInteger('epoch_number');
            $t->unsignedInteger('payload_schema');
            $this->digest($t, 'envelope_digest');
            $t->binary('signed_envelope');
            $t->binary('ciphertext');
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->timestamp('committed_at')->useCurrent();
            $t->unique(['object_id', 'revision_id']);
            $t->unique(['group_id', 'object_id', 'revision_id']);
            $t->unique(['author_account_id', 'author_device_id', 'operation_id'], 'revision_actor_operation');
            $t->index(['group_id', 'object_id', 'committed_at']);
            $t->foreign(['group_id', 'object_id'])->references(['group_id', 'id'])->on('objects')->restrictOnDelete();
            $t->foreign(['author_account_id', 'author_device_id'])->references(['account_id', 'id'])->on('devices')->restrictOnDelete();
        });
        DB::statement('ALTER TABLE object_revisions MODIFY ciphertext MEDIUMBLOB NOT NULL');
        $this->table('object_key_wraps', function (Blueprint $t) {
            $this->id($t, 'revision_id');
            $t->primary('revision_id');
            $t->binary('wrap_record');
            $t->unsignedBigInteger('ciphertext_bytes');
            $t->foreign('revision_id')->references('revision_id')->on('object_revisions')->restrictOnDelete();
        });
        foreach (['revision_parents', 'object_heads'] as $table) {
            $this->table($table, function (Blueprint $t) use ($table) {
                $this->id($t, 'group_id');
                $this->id($t, 'object_id');
                $this->id($t, 'revision_id');
                if ($table === 'revision_parents') {
                    $this->id($t, 'parent_revision_id');
                    $t->primary(['revision_id', 'parent_revision_id']);
                    $t->foreign(['group_id', 'object_id', 'parent_revision_id'])->references(['group_id', 'object_id', 'revision_id'])->on('object_revisions')->restrictOnDelete();
                } else {
                    $t->primary(['object_id', 'revision_id']);
                }
                $t->foreign(['group_id', 'object_id', 'revision_id'])->references(['group_id', 'object_id', 'revision_id'])->on('object_revisions')->restrictOnDelete();
            });
        }
        $this->table('quota_ledgers', function (Blueprint $t) {
            $t->string('scope', 64)->primary();
            $t->unsignedBigInteger('committed_bytes')->default(0);
            $t->unsignedBigInteger('reserved_bytes')->default(0);
            $t->unsignedBigInteger('limit_bytes');
            $t->unsignedBigInteger('pending_limit_bytes');
        });
        $this->table('quota_reservations', function (Blueprint $t) {
            $this->id($t);
            $t->primary('id');
            $this->id($t, 'account_id');
            $this->id($t, 'device_id');
            $this->id($t, 'group_id');
            $t->unsignedBigInteger('bytes');
            $t->unsignedBigInteger('committed_bytes')->default(0);
            $t->enum('state', ['reserved', 'committed', 'released']);
            $t->timestamp('expires_at');
            $t->index(['state', 'expires_at']);
            $t->foreign(['account_id', 'device_id'])->references(['account_id', 'id'])->on('devices')->restrictOnDelete();
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        $this->table('sync_counters', function (Blueprint $t) {
            $t->unsignedTinyInteger('id')->primary();
            $this->id($t, 'generation');
            $t->unsignedBigInteger('sequence')->default(0);
        });
        $this->table('sync_events', function (Blueprint $t) {
            $t->unsignedBigInteger('sequence')->primary();
            $this->id($t, 'event_id');
            $t->unique('event_id');
            $this->id($t, 'group_id');
            $t->char('audience_account_id', 22)->nullable();
            $t->string('kind', 32);
            $this->id($t, 'object_id');
            $t->char('revision_id', 22)->nullable();
            $this->digest($t, 'digest');
            $t->index(['group_id', 'sequence']);
            $t->index(['audience_account_id', 'sequence']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        $this->table('mutation_receipts', function (Blueprint $t) {
            $this->id($t, 'account_id');
            $this->id($t, 'device_id');
            $this->id($t, 'operation_id');
            $t->string('family', 32);
            $t->primary(['account_id', 'device_id', 'operation_id']);
            $this->id($t, 'group_id');
            $this->digest($t, 'request_digest');
            $t->binary('result');
            $t->timestamp('expires_at');
            $t->index('expires_at');
            $t->foreign(['account_id', 'device_id'])->references(['account_id', 'id'])->on('devices')->restrictOnDelete();
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        $this->table('runtime_heartbeats', function (Blueprint $t) {
            $t->string('component', 32)->primary();
            $t->timestamp('observed_at');
        });
        $this->table('jobs', function (Blueprint $t) {
            $t->bigIncrements('id');
            $t->string('queue')->index();
            $t->longText('payload');
            $t->unsignedTinyInteger('attempts');
            $t->unsignedInteger('reserved_at')->nullable();
            $t->unsignedInteger('available_at');
            $t->unsignedInteger('created_at');
        });
        // Jobs contain fixed maintenance identifiers, never user content, keys or tokens.
        DB::table('sync_counters')->insert(['id' => 1, 'generation' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=')]);
        DB::table('quota_ledgers')->insert([
            ['scope' => 'global', 'limit_bytes' => 100000000000, 'pending_limit_bytes' => 5368709120],
            ['scope' => 'security', 'limit_bytes' => 268435456, 'pending_limit_bytes' => 268435456],
        ]);
    }

    public function down(): void
    {
        foreach (['jobs', 'runtime_heartbeats', 'mutation_receipts', 'sync_events', 'sync_counters', 'quota_reservations', 'quota_ledgers', 'object_heads', 'revision_parents', 'object_key_wraps', 'object_revisions', 'objects', 'group_memberships', 'groups', 'account_invites', 'auth_sessions', 'devices', 'account_identities', 'users'] as $table) {
            Schema::dropIfExists($table);
        }
    }
};
