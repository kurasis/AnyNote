<?php

namespace App\Auth;

use Illuminate\Support\Facades\DB;

final class Maintenance
{
    /** Bounded expiry cleanup. Retain used refresh hashes throughout their full 30-day lifetime. */
    public function prune(): int
    {
        return DB::transaction(function () {
            DB::table('operator_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $count = 0;
            foreach (['auth_challenges', 'auth_registrations', 'auth_registration_receipts', 'native_authorizations', 'oauth_codes', 'oauth_access', 'auth_rate_buckets'] as $table) {
                $count += DB::table($table)->where('expires_at', '<', $table === 'auth_rate_buckets' ? now() : now()->subDay())->limit(1000)->delete();
            }
            $count += DB::table('refresh_tokens')->where('expires_at', '<', now()->subDay())->limit(1000)->delete();
            $count += DB::table('device_transition_receipts')->where('expires_at', '<', now())->limit(1000)->delete();
            $count += DB::table('account_security_notifications')->where('created_at', '<', now()->subDays(30))->limit(1000)->delete();
            // Never delete a still-refreshable native family, durable device, root, roster or content.
            $ids = DB::table('auth_sessions')->whereNotNull('absolute_expires_at')->where('absolute_expires_at', '<', now()->subDay())->limit(100)->pluck('id');
            foreach ($ids as $id) {
                $s = DB::table('auth_sessions')->where('id', $id)->first();
                DB::table('oauth_codes')->where('session_id', $id)->delete();
                DB::table('oauth_access')->where('session_id', $id)->delete();
                if ($s->family_id !== null) {
                    DB::table('refresh_tokens')->where('family_id', $s->family_id)->delete();
                }
                $count += DB::table('auth_sessions')->where('id', $id)->delete();
            }

            return $count;
        }, 3);
    }
}
