<?php

namespace App\Operations;

use App\Http\ApiException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/** An operator-created fence survives database replacement; no HTTP unlock exists. */
final class RecoveryFence
{
    public function active(): bool
    {
        if (file_exists(config('operations.recovery_fence'))) {
            return true;
        }
        // Legacy installations may run their additive migration before this table
        // exists. Restore ALWAYS installs the external fence before importing SQL.
        if (! Schema::hasTable('operations_restore_state')) {
            return false;
        }
        $state = DB::table('operations_restore_state')->where('singleton', 1)->first();

        return ! $state || (bool) $state->quarantined;
    }

    public function admit(): void
    {
        if ($this->active()) {
            throw new ApiException('RESTORE_QUARANTINE');
        }
    }
}
