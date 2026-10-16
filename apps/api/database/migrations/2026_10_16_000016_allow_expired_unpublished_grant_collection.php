<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // A committed staging parent cannot be relabelled to evade the page guard.
        foreach (['UPDATE', 'DELETE'] as $action) {
            DB::unprepared('CREATE TRIGGER committed_transition_'.strtolower($action).' BEFORE '.$action." ON security_transition_staging FOR EACH ROW BEGIN IF OLD.state = 'committed' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable committed transition'; END IF; END");
        }
        DB::unprepared('DROP TRIGGER immutable_security_transition_pages_delete');
        DB::unprepared("CREATE TRIGGER immutable_security_transition_pages_delete BEFORE DELETE ON security_transition_pages FOR EACH ROW BEGIN IF NOT EXISTS (SELECT 1 FROM security_transition_staging s WHERE s.id = OLD.transition_id AND s.state IN ('expired', 'cancelled') AND s.pending_group_id IS NULL AND s.expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Immutable committed or live grant page'; END IF; END");
    }

    public function down(): void
    {
        throw new LogicException('Committed transition guards require a reviewed data-preserving rollback');
    }
};
