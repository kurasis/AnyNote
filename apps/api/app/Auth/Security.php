<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class Security
{
    public function __construct(private Sessions $sessions) {}

    /** Logout is idempotent even for expired/disabled browser sessions. It only removes authority. */
    public function logout(Request $r): array
    {
        $secret = $r->hasSession() ? $r->session()->get('auth_secret') : $this->sessions->secret($r);
        DB::transaction(function () use ($secret, $r) {
            $s = is_string($secret) ? DB::table('auth_sessions')->where('secret_hash', hash('sha256', $secret))->first() : null;
            if ($s && $s->transport === ($r->headers->has('Authorization') ? 'native' : 'pwa')) {
                DB::table('users')->where('id', $s->account_id)->lockForUpdate()->first();
                Sessions::revoke($s->id);
            }
        }, 3);
        if ($r->hasSession()) {
            $r->session()->invalidate();
            $r->session()->regenerateToken();
        }

        return ['version' => 1, 'status' => 'ok', ...($r->hasSession() ? ['csrf_token' => $r->session()->token()] : [])];
    }

    public function codes(Request $r): array
    {
        return DB::transaction(function () use ($r) {
            $s = $this->sessions->current($r, true);
            Sessions::recent($s);
            // Replacing an authentication recovery set invalidates the previous set atomically.
            DB::table('auth_recovery_codes')->where('account_id', $s->account_id)->delete();
            $codes = [];
            for ($i = 0; $i < 10; $i++) {
                $codes[] = $code = P::b64(random_bytes(32));
                DB::table('auth_recovery_codes')->insert(['id' => P::b64(random_bytes(16)), 'account_id' => $s->account_id, 'code_hash' => hash('sha256', $code)]);
            }

            return ['version' => 1, 'codes' => $codes];
        }, 3);
    }

    public function recover(Request $r, string $code): array
    {
        if ($r->session()->has('auth_secret')) {
            throw new ApiException('AUTH_REQUIRED');
        }

        return DB::transaction(function () use ($r, $code) {
            $candidate = DB::table('auth_recovery_codes')->where('code_hash', hash('sha256', $code))->first();
            if (! $candidate) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $u = DB::table('users')->where('id', $candidate->account_id)->lockForUpdate()->first();
            $c = DB::table('auth_recovery_codes')->where('id', $candidate->id)->lockForUpdate()->first();
            if (! $u || $u->status !== 'active' || $c->consumed_at !== null) {
                throw new ApiException('AUTH_REQUIRED');
            }
            DB::table('auth_recovery_codes')->where('id', $c->id)->update(['consumed_at' => now()]);

            return $this->sessions->create($r, $u->id);
        }, 3);
    }

    public function removePasskey(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $s = $this->sessions->current($r, true);
            Sessions::recent($s);
            $k = DB::table('passkey_credentials')->where('id', $id)->where('account_id', $s->account_id)->lockForUpdate()->first();
            if (! $k) {
                throw new ApiException('NOT_FOUND');
            }
            if (DB::table('passkey_credentials')->where('account_id', $s->account_id)->count() <= 1 && ! DB::table('auth_recovery_codes')->where('account_id', $s->account_id)->whereNull('consumed_at')->exists()) {
                throw new ApiException('ROLE_FORBIDDEN');
            }
            DB::table('passkey_credentials')->where('id', $id)->delete();

            return ['version' => 1, 'status' => 'ok', ...($s->transport === 'pwa' ? ['csrf_token' => $r->session()->token()] : [])];
        }, 3);
    }

    public function revoke(Request $r, ?string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $s = $this->sessions->current($r, true);
            if ($id !== null && $id !== $s->id) {
                Sessions::recent($s);
            }
            $target = DB::table('auth_sessions')->where('id', $id ?? $s->id)->where('account_id', $s->account_id)->lockForUpdate()->first();
            if (! $target) {
                throw new ApiException('NOT_FOUND');
            }
            Sessions::revoke($target->id);
            if ($s->id === $target->id && $s->transport === 'pwa') {
                $r->session()->invalidate();
                $r->session()->regenerateToken();
            }

            return ['version' => 1, 'status' => 'ok', ...($s->transport === 'pwa' ? ['csrf_token' => $r->session()->token()] : [])];
        }, 3);
    }

    public function revokeAll(Request $r): array
    {
        return DB::transaction(function () use ($r) {
            $s = $this->sessions->current($r, true);
            Sessions::recent($s);
            foreach (DB::table('auth_sessions')->where('account_id', $s->account_id)->where('state', '!=', 'revoked')->lockForUpdate()->get()->pluck('id') as $id) {
                Sessions::revoke($id);
            }
            if ($s->transport === 'pwa') {
                $r->session()->invalidate();
                $r->session()->regenerateToken();
            }

            return ['version' => 1, 'status' => 'ok', ...($s->transport === 'pwa' ? ['csrf_token' => $r->session()->token()] : [])];
        }, 3);
    }
}
