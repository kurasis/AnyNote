<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_sessions', function (Blueprint $t) {
            $t->char('device_id', 22)->nullable()->change();
            $t->string('transport', 8)->default('legacy');
            $t->char('family_id', 22)->nullable()->unique();
            $t->timestamp('absolute_expires_at')->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->timestamp('created_at')->useCurrent();
            $t->char('device_commitment', 43)->nullable();
        });
        Schema::table('account_invites', function (Blueprint $t) {
            $t->char('creator_id', 22)->nullable()->change();
            $t->boolean('bootstrap')->default(false);
        });
        Schema::table('passkey_credentials', function (Blueprint $t) {
            $t->text('credential_id')->nullable();
            $t->timestamp('created_at')->useCurrent();
        });
        Schema::table('refresh_tokens', function (Blueprint $t) {
            $t->char('device_id', 22)->nullable()->change();
            $t->string('oauth_identifier', 100)->nullable()->unique();
        });
        foreach (['auth_challenges', 'auth_registrations', 'native_authorizations', 'oauth_codes', 'oauth_access', 'auth_rate_buckets', 'sessions', 'auth_registration_receipts'] as $name) {
            Schema::create($name, function (Blueprint $t) use ($name) {
                $t->engine = 'InnoDB';
                $t->charset = 'ascii';
                $t->collation = 'ascii_bin';
                if ($name === 'sessions') {
                    $t->string('id', 255)->primary();
                    $t->string('user_id', 22)->nullable()->index();
                    $t->string('ip_address', 45)->nullable();
                    $t->text('user_agent')->nullable();
                    $t->longText('payload');
                    $t->integer('last_activity')->index();
                } elseif ($name === 'auth_rate_buckets') {
                    $t->char('id', 64)->primary();
                    $t->unsignedInteger('attempts');
                    $t->timestamp('expires_at')->index();
                } elseif ($name === 'oauth_codes' || $name === 'oauth_access') {
                    $t->string('id', 100)->primary();
                    $t->char('session_id', 22);
                    $t->boolean('revoked')->default(false);
                    $t->timestamp('expires_at')->index();
                    $t->foreign('session_id')->references('id')->on('auth_sessions');
                    if ($name === 'oauth_codes') {
                        $t->char('authorization_id', 22);
                    }
                } else {
                    $t->char('id', 22)->primary();
                    $t->char('account_id', 22)->nullable()->index();
                    $t->char('binding_hash', 64);
                    $t->timestamp('expires_at')->index();
                    $t->timestamp('consumed_at')->nullable();
                    $t->binary('data');
                    if ($name === 'auth_challenges') {
                        $t->string('purpose', 24);
                    }
                    if ($name === 'auth_registrations') {
                        $t->char('invitation_id', 22);
                        $t->boolean('verified')->default(false);
                        $t->char('root_fingerprint', 43)->nullable();
                    }
                    if ($name === 'auth_registration_receipts') {
                        $t->char('request_digest', 64);
                    }
                }
            });
        }
        DB::statement('ALTER TABLE auth_challenges MODIFY data MEDIUMBLOB NOT NULL');
    }

    public function down(): void
    {
        // Deployed rollback requires an explicit operator migration plan; no destructive down helper.
        throw new LogicException('Authentication rollback requires an explicit data-preserving plan');
    }
};
