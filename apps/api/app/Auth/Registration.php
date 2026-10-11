<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

final class Registration
{
    public function __construct(private Proof $proof, private Sessions $sessions, private Passkeys $passkeys, private WebAuthn $verifier) {}

    private function identity(stdClass $i, string $account): string
    {
        if ($i->body->account_id !== $account || $i->body->service_id !== config('api.service_id') || $i->body->root_signing_key === $i->body->recovery_encryption_key) {
            throw new ApiException('AUTH_REQUIRED');
        }
        P::verify('p02-identity-c1', 'account-root-identity', $i->body, $i->signature, $i->body->root_signing_key);

        return P::digest('p02-identity-c1', 'account-root-identity', $i->body);
    }

    public function prepare(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $reg = DB::table('auth_registrations')->where('id', $body->registration_id)->lockForUpdate()->first();
            if (! $reg || ! $reg->verified || $reg->consumed_at !== null || $reg->expires_at <= now()->format('Y-m-d H:i:s') || $reg->binding_hash !== Sessions::binding($r)) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $data = json_decode($reg->data, true);
            $root = $this->identity($body->identity, $reg->account_id);
            if (isset($data['challenge'])) {
                if ($root !== $reg->root_fingerprint || P::canonical($body->device) !== P::canonical(json_decode(json_encode($data['challenge']['context']['device'])))) {
                    throw new ApiException('AUTH_REQUIRED');
                }

                return ['version' => 1, 'challenge' => $data['challenge']];
            }
            $caps = ['delegate-device', 'distribute-group-key', 'receive-group-key', 'sign-content'];
            if ($body->device->capabilities !== $caps || $body->device->signing_key === $body->device->encryption_key) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $challenge = $this->proof->issue($reg->account_id, $root, $body->device, $data['session_id'], 'register', '0', null, $reg->binding_hash);
            $data['challenge'] = $challenge;
            DB::table('auth_registrations')->where('id', $reg->id)->update(['root_fingerprint' => $root, 'data' => json_encode($data, JSON_THROW_ON_ERROR)]);

            return ['version' => 1, 'challenge' => $challenge];
        }, 3);
    }

    public function register(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            // The invitation locks first and serializes simultaneous registrations with different handles.
            $candidate = DB::table('auth_registrations')->where('id', $body->registration_id)->first();
            if (! $candidate) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $invite = DB::table('account_invites')->where('id', $candidate->invitation_id)->lockForUpdate()->first();
            $reg = DB::table('auth_registrations')->where('id', $candidate->id)->lockForUpdate()->first();
            $digest = P::b64(hash('sha256', P::canonical($body), true));
            $receipt = DB::table('auth_registration_receipts')->where('id', $reg->id)->first();
            if ($receipt) {
                if ($receipt->binding_hash !== Sessions::binding($r) || $receipt->request_digest !== $digest || $receipt->expires_at <= now()->format('Y-m-d H:i:s')) {
                    throw new ApiException('AUTH_REQUIRED');
                }
                $s = $this->sessions->current($r, true);
                if ($s->account_id !== $reg->account_id || $s->id !== json_decode($reg->data)->session_id) {
                    throw new ApiException('AUTH_REQUIRED');
                }

                return [...$this->sessions->result($r, $s), 'receipt' => json_decode($receipt->data)];
            }
            if (! $invite || $invite->status !== 'pending' || $invite->expires_at <= now()->format('Y-m-d H:i:s') || ! $reg->verified || $reg->consumed_at !== null || $reg->expires_at <= now()->format('Y-m-d H:i:s') || $reg->binding_hash !== Sessions::binding($r)) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $data = json_decode($reg->data);
            $root = $this->identity($body->identity, $reg->account_id);
            if ($root !== $reg->root_fingerprint || ! isset($data->challenge) || ($invite->recipient_binding_hash !== null && $invite->recipient_binding_hash !== hash('sha256', $data->handle))) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $event = $body->roster;
            $b = $event->body;
            $c = $b->payload->certificate;
            $cb = $c->body;
            $device = Proof::device($c);
            if ($b->kind !== 'register' || $b->signer !== 'root' || $b->generation !== '0' || $b->version !== '0' || $b->predecessor !== null || $b->account_id !== $reg->account_id || $b->service_id !== config('api.service_id') || $b->root_fingerprint !== $root || $b->operation_id !== $body->operation_id || $b->payload->active_device_limit !== '5' || P::canonical($b->payload->challenge) !== P::canonical($data->challenge) || P::canonical($device) !== P::canonical($data->challenge->context->device) || $cb->recovery_generation !== '0' || $cb->predecessor_roster !== null || $cb->issuer->kind !== 'root' || $cb->issuer->root_fingerprint !== $root || $cb->account_id !== $reg->account_id || $cb->service_id !== config('api.service_id') || $cb->root_fingerprint !== $root || $cb->pairing_transcript_digest !== P::digest('p02-state-c1', 'challenge', $data->challenge)) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $challenge = DB::table('auth_challenges')->where('id', $data->challenge->context->challenge_id)->lockForUpdate()->first();
            if (! $challenge || $challenge->consumed_at !== null || $challenge->expires_at <= now()->format('Y-m-d H:i:s')) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $this->proof->validate($data->challenge, $b->payload->confirmation, $data->session_id);
            P::verify('p02-identity-c1', 'provisional-device-certificate', $cb, $c->signature, $body->identity->body->root_signing_key);
            P::verify('p02-state-c1', 'device-roster-event', $b, $event->signature, $body->identity->body->root_signing_key);
            if (DB::table('users')->where('login_handle', $data->handle)->exists() || DB::table('account_identities')->where('root_fingerprint', $root)->exists() || DB::table('devices')->where('id', $device->device_id)->exists()) {
                throw new ApiException('AUTH_REQUIRED');
            }
            $roster = P::digest('p02-state-c1', 'event', $event);
            DB::table('users')->insert(['id' => $reg->account_id, 'login_handle' => $data->handle, 'status' => 'active']);
            DB::table('account_identities')->insert(['account_id' => $reg->account_id, 'root_fingerprint' => $root, 'identity_record' => P::canonical($body->identity), 'recovery_generation' => 0, 'roster_sequence' => 0, 'roster_digest' => $roster]);
            DB::table('devices')->insert(['id' => $device->device_id, 'account_id' => $reg->account_id, 'signing_key' => $device->signing_key, 'encryption_key' => $device->encryption_key, 'certificate_digest' => P::digest('p02-identity-c1', 'device-certificate', $c), 'certificate_record' => P::canonical($c), 'recovery_generation' => 0, 'status' => 'active', 'can_sign_content' => true]);
            DB::table('account_roster_events')->insert(['id' => $body->operation_id, 'account_id' => $reg->account_id, 'sequence' => 0, 'parent_digest' => null, 'digest' => $roster, 'signed_record' => P::canonical($event)]);
            $this->passkeys->persist($reg->account_id, $this->verifier->record($data->credential));
            DB::table('account_invites')->where('id', $invite->id)->update(['status' => 'consumed']);
            DB::table('auth_challenges')->where('id', $challenge->id)->update(['consumed_at' => now()]);
            DB::table('auth_registrations')->where('id', $reg->id)->update(['consumed_at' => now(), 'expires_at' => now()->addDays(30)]);
            $result = $this->sessions->create($r, $reg->account_id, $device->device_id, $data->session_id);
            DB::table('auth_sessions')->where('id', $data->session_id)->update(['device_commitment' => Proof::commitment($device)]);
            $receipt = (object) ['operation_id' => $body->operation_id, 'account_id' => $reg->account_id, 'root_fingerprint' => $root, 'roster_digest' => $roster];
            DB::table('auth_registration_receipts')->insert(['id' => $reg->id, 'account_id' => $reg->account_id, 'binding_hash' => $reg->binding_hash, 'request_digest' => $digest, 'expires_at' => now()->addDays(30), 'data' => P::canonical($receipt)]);

            return [...$result, 'receipt' => $receipt];
        }, 3);
    }

    public function bootstrap(int $hours): string
    {
        if (! app()->runningInConsole() || $hours < 1 || $hours > 48) {
            throw new ApiException('INVALID_REQUEST');
        }

        return DB::transaction(function () use ($hours) {
            DB::table('operator_coordination')->where('singleton', 1)->lockForUpdate()->first();
            if (DB::table('users')->exists() || DB::table('account_invites')->where('bootstrap', true)->where('status', 'pending')->where('expires_at', '>', now())->exists()) {
                throw new ApiException('ROLE_FORBIDDEN');
            }
            $token = P::b64(random_bytes(32));
            DB::table('account_invites')->insert(['id' => P::b64(random_bytes(16)), 'creator_id' => null, 'bootstrap' => true, 'token_hash' => hash('sha256', $token), 'recipient_binding_hash' => null, 'status' => 'pending', 'expires_at' => now()->addHours($hours)]);

            return $token;
        }, 3);
    }
}
