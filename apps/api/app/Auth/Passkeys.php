<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;
use Throwable;
use Webauthn\CredentialRecord;

final class Passkeys
{
    public function __construct(private WebAuthn $verifier, private Sessions $sessions) {}

    public function options(Request $r, stdClass $body): array
    {
        if (DB::table('auth_challenges')->count() >= 50000 || DB::table('auth_registrations')->count() >= 50000) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $kind = $body->ceremony;
        $binding = Sessions::binding($r);
        $account = null;
        $registration = null;
        $data = [];
        if ($kind === 'register') {
            if (! isset($body->invitation, $body->handle) || $r->session()->has('auth_secret')) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $invite = DB::table('account_invites')->where('token_hash', hash('sha256', $body->invitation))->first();
            if (! $invite || $invite->status !== 'pending' || $invite->expires_at <= now()->format('Y-m-d H:i:s') || ($invite->recipient_binding_hash !== null && ! hash_equals($invite->recipient_binding_hash, hash('sha256', $body->handle)))) {
                throw new ApiException('AUTH_REQUIRED');
            }
            if (DB::table('auth_registrations')->where('invitation_id', $invite->id)->whereNull('consumed_at')->where('expires_at', '>', now())->count() >= 5) {
                throw new ApiException('RESOURCE_LIMIT');
            }
            $registration = P::b64(random_bytes(16));
            $account = P::b64(random_bytes(16));
            $options = $this->verifier->createOptions($account, $body->handle);
            $data = ['registration_id' => $registration];
            DB::table('auth_registrations')->insert(['id' => $registration, 'account_id' => $account, 'invitation_id' => $invite->id, 'binding_hash' => $binding, 'expires_at' => now()->addMinutes(10), 'data' => json_encode(['handle' => $body->handle, 'session_id' => P::b64(random_bytes(16))], JSON_THROW_ON_ERROR)]);
        } elseif ($kind === 'login') {
            if (isset($body->invitation, $body->handle) || isset($body->invitation) || isset($body->handle)) {
                throw new ApiException('INVALID_REQUEST');
            }
            // New account login always starts a new restricted session, never reuses old device proof.
            if ($r->session()->has('auth_secret')) {
                $oldSecret = $r->session()->get('auth_secret');
                DB::transaction(function () use ($oldSecret) {
                    $old = DB::table('auth_sessions')->where('secret_hash', hash('sha256', $oldSecret))->where('transport', 'pwa')->first();
                    if ($old) {
                        DB::table('users')->where('id', $old->account_id)->lockForUpdate()->first();
                        Sessions::revoke($old->id);
                    }
                }, 3);
                $r->session()->invalidate();
                $r->session()->regenerateToken();
                $binding = Sessions::binding($r);
            }
            $options = $this->verifier->getOptions();
        } else {
            $s = $this->sessions->current($r);
            $account = $s->account_id;
            if (isset($body->invitation) || isset($body->handle)) {
                throw new ApiException('INVALID_REQUEST');
            }
            $data = ['session_id' => $s->id];
            if ($kind === 'add') {
                Sessions::recent($s);
                $records = DB::table('passkey_credentials')->where('account_id', $account)->pluck('flags')->all();
                if (count($records) >= 20) {
                    throw new ApiException('RESOURCE_LIMIT');
                }
                $options = $this->verifier->createOptions($account, DB::table('users')->where('id', $account)->value('login_handle'), $records);
            } else {
                $options = $this->verifier->getOptions();
            }
        }
        if (DB::table('auth_challenges')->where('binding_hash', $binding)->whereNull('consumed_at')->where('expires_at', '>', now())->count() >= 10) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $id = P::b64(random_bytes(16));
        $data['options'] = $options;
        DB::table('auth_challenges')->insert(['id' => $id, 'account_id' => $account, 'binding_hash' => $binding, 'purpose' => $kind, 'expires_at' => now()->addMinutes(2), 'data' => json_encode($data, JSON_THROW_ON_ERROR)]);
        $result = ['version' => 1, 'challenge_id' => $id, 'ceremony' => $kind, 'publicKey' => json_decode($options), 'csrf_token' => $r->session()->token()];
        if ($registration !== null) {
            $result['registration_id'] = $registration;
            $result['account_id'] = $account;
        }

        return $result;
    }

    public function verify(Request $r, stdClass $body, ?string $requiredPurpose = null): array
    {
        $binding = Sessions::binding($r);
        // A failed attempt consumes its own challenge. Catch inside the transaction so denial persists.
        $result = DB::transaction(function () use ($r, $body, $binding, $requiredPurpose) {
            $candidate = DB::table('auth_challenges')->where('id', $body->challenge_id)->first();
            $credential = DB::table('passkey_credentials')->where('credential_digest', hash('sha256', P::binary($body->credential->id)))->first();
            $account = $candidate?->account_id ?? $credential?->account_id;
            if ($account !== null) {
                DB::table('users')->where('id', $account)->lockForUpdate()->first();
            }
            $ch = DB::table('auth_challenges')->where('id', $body->challenge_id)->lockForUpdate()->first();
            if (! $ch || ($requiredPurpose !== null && $ch->purpose !== $requiredPurpose) || $ch->binding_hash !== $binding || $ch->consumed_at !== null || $ch->expires_at <= now()->format('Y-m-d H:i:s')) {
                return new ApiException('AUTH_REQUIRED');
            }
            DB::table('auth_challenges')->where('id', $ch->id)->update(['consumed_at' => now()]);
            try {
                return DB::transaction(function () use ($r, $body, $binding, $ch, $credential, $account) {
                    $data = json_decode($ch->data, true, 32, JSON_THROW_ON_ERROR);
                    if ($ch->purpose === 'register') {
                        $reg = DB::table('auth_registrations')->where('id', $data['registration_id'])->lockForUpdate()->first();
                        if (! $reg || $reg->verified || $reg->binding_hash !== $binding || $reg->expires_at <= now()->format('Y-m-d H:i:s') || $reg->consumed_at !== null) {
                            throw new ApiException('AUTH_REQUIRED');
                        }
                        $record = $this->verifier->registration($body->credential, $data['options']);
                        if ($record->userHandle !== P::binary($reg->account_id) || $credential !== null) {
                            throw new ApiException('AUTH_REQUIRED');
                        }
                        $saved = json_decode($reg->data, true);
                        $saved['credential'] = $this->verifier->serialize($record);
                        DB::table('auth_registrations')->where('id', $reg->id)->update(['verified' => true, 'data' => json_encode($saved, JSON_THROW_ON_ERROR)]);

                        return ['version' => 1, 'registration_id' => $reg->id, 'account_id' => $reg->account_id, 'verified' => true];
                    }
                    $user = DB::table('users')->where('id', $account)->lockForUpdate()->first();
                    if (! $user || $user->status !== 'active') {
                        throw new ApiException('AUTH_REQUIRED');
                    }
                    if ($ch->purpose === 'add') {
                        $s = $this->sessions->current($r, true);
                        Sessions::recent($s);
                        if ($s->id !== $data['session_id'] || $s->account_id !== $ch->account_id || $credential !== null) {
                            throw new ApiException('AUTH_REQUIRED');
                        }
                        $record = $this->verifier->registration($body->credential, $data['options']);
                        if ($record->userHandle !== P::binary($account)) {
                            throw new ApiException('AUTH_REQUIRED');
                        }
                        $this->persist($account, $record);

                        return ['version' => 1, 'status' => 'ok'];
                    }
                    if ($credential !== null && $credential->account_id !== $account) {
                        throw new ApiException('AUTH_REQUIRED');
                    }
                    $credential = DB::table('passkey_credentials')->where('credential_digest', hash('sha256', P::binary($body->credential->id)))->lockForUpdate()->first();
                    if (! $credential || $credential->account_id !== $account || ($ch->account_id !== null && $ch->account_id !== $credential->account_id)) {
                        throw new ApiException('AUTH_REQUIRED');
                    }
                    $record = $this->verifier->assertion($body->credential, $data['options'], $credential->flags);
                    DB::table('passkey_credentials')->where('id', $credential->id)->update(['counter' => $record->counter, 'flags' => $this->verifier->serialize($record)]);
                    if ($ch->purpose === 'reauth') {
                        $s = $this->sessions->current($r, true);
                        if ($s->id !== $data['session_id'] || $s->account_id !== $account) {
                            throw new ApiException('AUTH_REQUIRED');
                        }
                        DB::table('auth_sessions')->where('id', $s->id)->update(['authenticated_at' => now()]);

                        return $this->sessions->result($r, DB::table('auth_sessions')->where('id', $s->id)->first());
                    }

                    return $this->sessions->create($r, $account);
                });
            } catch (Throwable $e) {
                return $e instanceof ApiException ? $e : new ApiException('AUTH_REQUIRED');
            }
        }, 3);
        if ($result instanceof ApiException) {
            throw $result;
        }

        return $result;
    }

    public function persist(string $account, CredentialRecord $record): void
    {
        if (DB::table('passkey_credentials')->where('account_id', $account)->lockForUpdate()->limit(20)->get()->count() >= 20 || DB::table('passkey_credentials')->where('credential_digest', hash('sha256', $record->publicKeyCredentialId))->exists()) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        DB::table('passkey_credentials')->insert(['id' => P::b64(random_bytes(16)), 'account_id' => $account, 'credential_digest' => hash('sha256', $record->publicKeyCredentialId), 'credential_id' => P::b64($record->publicKeyCredentialId), 'public_key' => $record->credentialPublicKey, 'counter' => $record->counter, 'flags' => $this->verifier->serialize($record)]);
    }
}
