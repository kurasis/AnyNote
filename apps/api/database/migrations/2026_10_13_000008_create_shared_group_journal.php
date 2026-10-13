<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('shared_group_geneses', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('group_id', 22)->primary();
            $t->char('account_id', 22);
            $t->char('device_id', 22);
            $t->char('operation_id', 22);
            $t->char('request_digest', 43);
            $t->binary('commit_record');
            $t->binary('grant_page');
            $t->unique(['account_id', 'device_id', 'operation_id'], 'shared_genesis_actor_operation');
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('group_transition_journal', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('group_id', 22);
            $t->unsignedBigInteger('position');
            $t->binary('record');
            $t->primary(['group_id', 'position']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('group_security_receipts', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('account_id', 22);
            $t->char('device_id', 22);
            $t->char('operation_id', 22);
            $t->char('family', 16);
            $t->char('group_id', 22);
            $t->char('request_digest', 43);
            $t->binary('result');
            $t->primary(['account_id', 'device_id', 'operation_id', 'family'], 'group_security_receipt_actor');
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        Schema::create('account_closure_queue', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('account_id', 22)->primary();
            $t->char('operation_id', 22)->unique();
            $t->char('request_digest', 43);
            $t->timestamp('requested_at');
            $t->timestamp('not_before');
            $t->enum('state', ['pending-retention']);
            $t->foreign('account_id')->references('id')->on('users')->restrictOnDelete();
        });
        Schema::create('group_owner_consents', function (Blueprint $t) {
            $t->engine = 'InnoDB';
            $t->charset = 'ascii';
            $t->collation = 'ascii_bin';
            $t->char('group_id', 22);
            $t->char('policy_digest', 43);
            $t->char('account_id', 22);
            $t->char('device_id', 22);
            $t->char('session_id', 22);
            $t->timestamp('expires_at');
            $t->primary(['group_id', 'policy_digest']);
            $t->foreign('group_id')->references('id')->on('groups')->restrictOnDelete();
        });
        DB::unprepared('ALTER TABLE security_transition_staging MODIFY signed_descriptor MEDIUMBLOB NOT NULL, MODIFY expected_rosters MEDIUMBLOB NOT NULL');
        DB::unprepared('ALTER TABLE security_transition_pages MODIFY page_record MEDIUMBLOB NOT NULL');
        DB::unprepared('ALTER TABLE shared_group_geneses MODIFY commit_record MEDIUMBLOB NOT NULL, MODIFY grant_page MEDIUMBLOB NOT NULL');
        DB::unprepared('ALTER TABLE group_transition_journal MODIFY record MEDIUMBLOB NOT NULL');
        foreach (['group_transition_journal', 'group_security_receipts', 'shared_group_geneses'] as $table) {
            foreach (['UPDATE', 'DELETE'] as $action) {
                DB::unprepared("CREATE TRIGGER {$table}_immutable_".strtolower($action)." BEFORE {$action} ON {$table} FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable security evidence'");
            }
        }
    }

    public function down(): void
    {
        foreach (['account_closure_queue', 'group_owner_consents', 'group_security_receipts', 'group_transition_journal', 'shared_group_geneses'] as $table) {
            Schema::dropIfExists($table);
        }
    }
};
