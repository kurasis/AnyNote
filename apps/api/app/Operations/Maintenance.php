<?php

namespace App\Operations;

use Illuminate\Support\Facades\DB;

/** Only expired unpublished grants; burned commitments and committed history survive. */
final class Maintenance
{
    public function security(): int
    {
        $removed = 0;
        foreach (DB::table('security_transition_staging')->whereIn('state', ['staged', 'cancelled', 'expired'])->where('expires_at', '<', now()->subDay())->orderBy('id')->limit(25)->get() as $hint) {
            $removed += DB::transaction(function () use ($hint) {
                DB::table('groups')->where('id', $hint->group_id)->lockForUpdate()->first();
                $row = DB::table('security_transition_staging')->where('id', $hint->id)->lockForUpdate()->first();
                if (! $row || $row->state === 'committed' || $row->expires_at >= now()->subDay()->format('Y-m-d H:i:s')) {
                    return 0;
                }
                if ($row->state === 'staged') {
                    DB::table('security_transition_staging')->where('id', $row->id)->update(['pending_group_id' => null, 'state' => 'expired']);
                }
                DB::table('membership_invites')->where('id', $row->id)->whereIn('state', ['pending', 'accepted'])->update(['state' => 'expired']);

                // The descriptor retains every exposed/burned key commitment.
                // Never touch key_envelopes, committed pages, epochs or journals.
                return DB::table('security_transition_pages')->where('transition_id', $row->id)->limit(100)->delete();
            }, 3);
        }

        return $removed;
    }
}
