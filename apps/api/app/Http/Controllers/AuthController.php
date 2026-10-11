<?php

namespace App\Http\Controllers;

use App\Auth\Contracts;
use App\Auth\Native;
use App\Auth\Passkeys;
use App\Auth\Policy;
use App\Auth\Proof;
use App\Auth\RateLimits;
use App\Auth\Registration;
use App\Auth\Security;
use App\Auth\Sessions;
use App\Auth\WebAuthn;
use App\Backend\AccountAdministration;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class AuthController
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private RateLimits $limits) {}

    public function __invoke(Request $r)
    {
        Policy::check();
        $op = $r->route()->getName();
        if ($r->headers->has('Authorization') && ($r->headers->has('Origin') || $r->headers->has('Cookie'))) {
            throw new ApiException('AUTH_REQUIRED');
        }
        if ($r->headers->has('Authorization') && in_array($op, ['get_auth_csrf', 'post_auth_passkeys_options', 'post_auth_passkeys_verify', 'post_me_passkeys', 'post_accounts_register', 'post_accounts_registration_challenge', 'post_auth_recovery_code', 'post_auth_native_approve', 'get_auth_native_authorizations_id'], true)) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $native = in_array($op, ['get_auth_native_authorize', 'post_auth_native_token'], true);
        if ($native) {
            if ($r->headers->has('Origin') || $r->headers->has('Cookie') || $r->headers->has('Authorization')) {
                throw new ApiException('AUTH_REQUIRED');
            }
        } elseif (! $r->headers->has('Authorization') && $r->header('Origin') !== config('api.app_origin')) {
            throw new ApiException('NOT_FOUND');
        }
        // Independent IP admission prevents unlimited new-cookie challenges and recovery guesses.
        $this->limits->hit('ip-'.$op, $r->ip(), 60);
        if ($r->hasSession()) {
            $this->limits->hit('browser-'.$op, Sessions::binding($r), 20);
        }
        $id = $r->route('id');
        if ($id !== null && ! P::isBinary($id, 16)) {
            throw new ApiException('NOT_FOUND');
        }
        $kinds = [
            'post_auth_passkeys_options' => 'options-request', 'post_auth_passkeys_verify' => 'verify-request',
            'post_me_passkeys' => 'verify-request', 'delete_me_sessions' => 'empty-request',
            'post_accounts_registration_challenge' => 'registration-prepare-request', 'post_accounts_register' => 'register-request',
            'post_auth_device_challenge' => 'device-challenge-request', 'post_auth_device_proof' => 'device-proof-request',
            'post_auth_recovery_code' => 'recovery-request', 'post_auth_native_approve' => 'native-approve-request',
            'post_auth_native_token' => 'native-token-request', 'post_auth_logout' => 'empty-request', 'post_me_recovery_codes' => 'empty-request',
            'delete_me_sessions_id' => 'empty-request', 'delete_me_passkeys_id' => 'empty-request', 'post_admin_accounts_id_disable' => 'empty-request',
        ];
        $body = isset($kinds[$op]) ? $this->contracts->decode($kinds[$op], $r->getContent()) : null;
        if ($op === 'get_auth_native_authorize') {
            $q = [];
            foreach (explode('&', $r->server->get('QUERY_STRING', '')) as $part) {
                $pair = explode('=', $part, 2);
                if (count($pair) !== 2 || preg_match('/%(?![0-9A-Fa-f]{2})/', $part)) {
                    throw new ApiException('INVALID_REQUEST');
                }
                $key = urldecode($pair[0]);
                if (isset($q[$key])) {
                    throw new ApiException('INVALID_REQUEST');
                }
                $q[$key] = urldecode($pair[1]);
            }
            $body = $this->contracts->value('p06', 'native-authorize-request', (object) ['version' => 1, ...$q]);
        } elseif ($r->isMethod('GET') && ($r->getQueryString() !== null || $r->getContent() !== '')) {
            throw new ApiException('INVALID_REQUEST');
        }
        [$result, $shape] = match ($op) {
            'get_auth_csrf' => [['version' => 1, 'csrf_token' => $r->session()->token()], 'csrf-result'],
            'post_auth_passkeys_options' => [app(Passkeys::class)->options($r, $body), 'options-result'],
            'post_auth_passkeys_verify' => [app(Passkeys::class)->verify($r, $body), 'verify-result'],
            'post_me_passkeys' => [app(Passkeys::class)->verify($r, $body, 'add'), 'verify-result'],
            'delete_me_sessions' => [app(Security::class)->revokeAll($r), 'ok-result'],
            'post_accounts_registration_challenge' => [app(Registration::class)->prepare($r, $body), 'challenge-result'],
            'post_accounts_register' => [app(Registration::class)->register($r, $body), 'register-result'],
            'post_auth_device_challenge' => [app(Proof::class)->challenge($r, $body->device_id), 'challenge-result'],
            'post_auth_device_proof' => [app(Proof::class)->upgrade($r, $body), 'auth-result'],
            'post_auth_recovery_code' => [app(Security::class)->recover($r, $body->code), 'auth-result'],
            'post_me_recovery_codes' => [app(Security::class)->codes($r), 'recovery-codes-result'],
            'post_auth_logout' => [app(Security::class)->logout($r), 'ok-result'],
            'delete_me_sessions_id' => [app(Security::class)->revoke($r, $id), 'ok-result'],
            'delete_me_passkeys_id' => [app(Security::class)->removePasskey($r, $id), 'ok-result'],
            'get_me' => [$this->me($r), 'me-result'],
            'get_me_sessions' => [$this->sessionList($r), 'sessions-result'],
            'get_me_passkeys' => [$this->passkeyList($r), 'passkeys-result'],
            'post_admin_account_invitations' => [app(AccountAdministration::class)->invite($this->sessions->secret($r), $r->getContent()), 'p04/invite-result'],
            'post_admin_accounts_id_disable' => [$this->disable($r, $id), 'ok-result'],
            'get_auth_native_authorize' => [app(Native::class)->authorize($body), 'native-authorization-result'],
            'get_auth_native_authorizations_id' => [app(Native::class)->consent($r, $id), 'native-consent-result'],
            'post_auth_native_approve' => [app(Native::class)->approve($r, $body->authorization_id), 'native-approve-result'],
            'post_auth_native_token' => [app(Native::class)->token($body), 'native-token-result'],
            default => throw new ApiException('NOT_FOUND'),
        };
        if ($shape === 'p04/invite-result') {
            app(P::class)->decode('p04-api', 'invite-result', json_encode($result, JSON_THROW_ON_ERROR));
        } else {
            $this->contracts->value('p06', $shape, json_decode(json_encode($result, JSON_THROW_ON_ERROR)));
        }

        return response()->json($result);
    }

    private function me(Request $r): array
    {
        $s = $this->sessions->current($r);
        $i = DB::table('account_identities')->where('account_id', $s->account_id)->first();

        return ['version' => 1, 'session' => Sessions::public($s), 'root_fingerprint' => $i?->root_fingerprint, 'recent_auth' => $s->authenticated_at >= now()->subMinutes(5)->format('Y-m-d H:i:s'), 'is_admin' => (bool) DB::table('users')->where('id', $s->account_id)->value('is_admin'), 'content_access' => $s->state === 'trusted'];
    }

    private function sessionList(Request $r): array
    {
        $s = $this->sessions->current($r);
        $rows = Sessions::live($s->account_id)->orderBy('id')->limit(100)->get()->map(fn ($x) => ['id' => $x->id, 'current' => $x->id === $s->id, 'state' => $x->state, 'transport' => $x->transport, 'created_at' => (string) $x->created_at, 'expires_at' => (string) $x->expires_at, 'device_id' => $x->device_id])->all();

        return ['version' => 1, 'sessions' => $rows];
    }

    private function passkeyList(Request $r): array
    {
        $s = $this->sessions->current($r);
        $rows = DB::table('passkey_credentials')->where('account_id', $s->account_id)->orderBy('id')->limit(20)->get()->map(function ($x) {
            $record = app(WebAuthn::class)->record($x->flags);

            return ['id' => $x->id, 'created_at' => (string) $x->created_at, 'backup_eligible' => (bool) $record->backupEligible, 'backup_status' => (bool) $record->backupStatus];
        })->all();

        return ['version' => 1, 'passkeys' => $rows];
    }

    private function disable(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            // Administrative coordination serializes cross-account disable and avoids opposite lock order.
            DB::table('operator_coordination')->where('singleton', 1)->lockForUpdate()->first();
            $a = app(Authorization::class)->actor($this->sessions->secret($r));
            if (! $a->admin || ! $a->recent || $a->accountId === $id) {
                throw new ApiException('ROLE_FORBIDDEN');
            }
            $u = DB::table('users')->where('id', $id)->lockForUpdate()->first();
            if (! $u) {
                throw new ApiException('NOT_FOUND');
            }
            DB::table('users')->where('id', $id)->update(['status' => 'disabled']);
            foreach (DB::table('auth_sessions')->where('account_id', $id)->pluck('id') as $s) {
                Sessions::revoke($s);
            }

            return ['version' => 1, 'status' => 'ok'];
        }, 3);
    }
}
