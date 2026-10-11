<?php

namespace App\Auth;

use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Database\Query\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

final class Sessions
{
    public function __construct(private Authorization $authorization) {}

    public static function live(string $account): Builder
    {
        return DB::table('auth_sessions')->where('account_id', $account)->where('state', '!=', 'revoked')
            ->where(function ($q) {
                $q->where('expires_at', '>', now())->orWhere(function ($q) {
                    $q->where('transport', 'native')->where('absolute_expires_at', '>', now())
                        ->whereExists(function ($q) {
                            $q->selectRaw('1')->from('refresh_tokens')->whereColumn('refresh_tokens.family_id', 'auth_sessions.family_id')->where('refresh_tokens.state', 'active')->where('refresh_tokens.expires_at', '>', now());
                        });
                });
            });
    }

    public static function binding(Request $r): string
    {
        if (! $r->session()->has('auth_binding')) {
            $r->session()->put('auth_binding', P::b64(random_bytes(32)));
        }

        return hash_hmac('sha256', "AnyNote/P06/browser-binding\0".$r->session()->get('auth_binding'), (string) config('app.key'));
    }

    public static function proofBinding(string $id): string
    {
        return P::b64(hash('sha256', "AnyNote/P06/session-binding\0".$id, true));
    }

    public function secret(Request $r): string
    {
        $native = $r->headers->has('Authorization');
        if ($native) {
            if ($r->headers->has('Cookie') || $r->headers->has('Origin') || ! preg_match('/^Bearer ([A-Za-z0-9_.-]{20,8192})$/D', $r->header('Authorization'), $m)) {
                throw new ApiException('AUTH_REQUIRED');
            }

            return $m[1];
        }
        if ($r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('NOT_FOUND');
        }
        $s = $r->session()->get('auth_secret');
        if (! is_string($s) || ! P::isBinary($s, 32)) {
            throw new ApiException('AUTH_REQUIRED');
        }

        return $s;
    }

    public function current(Request $r, bool $lock = false): stdClass
    {
        if ($lock && DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
        $secret = $this->secret($r);
        $s = DB::table('auth_sessions')->where('secret_hash', hash('sha256', $secret))->first();
        if (! $s) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $q = DB::table('users')->where('id', $s->account_id);
        $u = ($lock ? $q->lockForUpdate() : $q)->first();
        if ($lock) {
            DB::table('account_identities')->where('account_id', $s->account_id)->lockForUpdate()->first();
        }
        $q = DB::table('auth_sessions')->where('id', $s->id);
        $s = ($lock ? $q->lockForUpdate() : $q)->first();
        if (! $u || $u->status !== 'active' || ! $s || ! hash_equals($s->secret_hash, hash('sha256', $secret)) || $s->state === 'revoked' || $s->expires_at <= now()->format('Y-m-d H:i:s') || ($s->absolute_expires_at !== null && $s->absolute_expires_at <= now()->format('Y-m-d H:i:s')) || ($r->headers->has('Authorization') ? $s->transport !== 'native' : $s->transport !== 'pwa')) {
            throw new ApiException('SESSION_EXPIRED');
        }
        if ($s->state === 'trusted') {
            $this->authorization->actor($secret, $lock);
        }
        if (! $lock && $s->transport === 'pwa') {
            DB::table('auth_sessions')->where('id', $s->id)->where('secret_hash', $s->secret_hash)->where('state', '!=', 'revoked')->where('expires_at', '>', now())->update(['last_seen_at' => now(), 'expires_at' => min(now()->addMinutes(30)->format('Y-m-d H:i:s'), $s->absolute_expires_at)]);
        }

        return $s;
    }

    public static function recent(stdClass $s): void
    {
        if ($s->authenticated_at < now()->subMinutes(5)->format('Y-m-d H:i:s')) {
            throw new ApiException('ROLE_FORBIDDEN');
        }
    }

    public static function public(stdClass $s): array
    {
        return ['id' => $s->id, 'account_id' => $s->account_id, 'device_id' => $s->device_id, 'state' => $s->state, 'generation' => (string) $s->recovery_generation];
    }

    public function create(Request $r, string $account, ?string $device = null, ?string $id = null): array
    {
        $old = $r->session()->get('auth_secret');
        if (is_string($old)) {
            $existing = DB::table('auth_sessions')->where('secret_hash', hash('sha256', $old))->first();
            if ($existing) {
                self::revoke($existing->id);
            }
        }
        $binding = $r->session()->get('auth_binding');
        $r->session()->invalidate();
        $r->session()->regenerateToken();
        $r->session()->put('auth_binding', $binding ?: P::b64(random_bytes(32)));
        $secret = P::b64(random_bytes(32));
        $identity = DB::table('account_identities')->where('account_id', $account)->first();
        $id ??= P::b64(random_bytes(16));
        if (self::live($account)->count() >= 100) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        DB::table('auth_sessions')->insert(['id' => $id, 'account_id' => $account, 'device_id' => $device, 'secret_hash' => hash('sha256', $secret), 'recovery_generation' => $identity?->recovery_generation ?? 0, 'state' => $device === null ? 'restricted' : 'trusted', 'expires_at' => now()->addMinutes(30), 'absolute_expires_at' => now()->addDays(30), 'authenticated_at' => now(), 'last_seen_at' => now(), 'transport' => 'pwa']);
        $r->session()->put('auth_secret', $secret);

        return $this->result($r, DB::table('auth_sessions')->where('id', $id)->first());
    }

    public function result(Request $r, stdClass $s): array
    {
        return ['version' => 1, 'session' => self::public($s), ...($s->transport === 'pwa' ? ['csrf_token' => $r->session()->token()] : [])];
    }

    public static function revoke(string $id): void
    {
        $s = DB::table('auth_sessions')->where('id', $id)->first();
        if (! $s) {
            return;
        }
        DB::table('auth_sessions')->where('id', $id)->update(['state' => 'revoked']);
        DB::table('oauth_access')->where('session_id', $id)->update(['revoked' => true]);
        DB::table('oauth_codes')->where('session_id', $id)->update(['revoked' => true]);
        if ($s->family_id !== null) {
            DB::table('refresh_tokens')->where('family_id', $s->family_id)->update(['state' => 'revoked']);
        }
    }
}
