<?php

namespace App\Auth;

use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Fresh possession of BOTH certified device keys; never accepts a device ID as proof. */
final class Proof
{
    public function __construct(private Contracts $contracts, private Sessions $sessions, private Authorization $authorization) {}

    public static function commitment(stdClass $device): string
    {
        return P::b64(hash('sha256', "AnyNote/P06/device-key-commitment\0".P::binary($device->signing_key).P::binary($device->encryption_key), true));
    }

    public static function device(stdClass $certificate): stdClass
    {
        $b = $certificate->body;

        return (object) ['device_id' => $b->device_id, 'signing_key' => $b->device_signing_key, 'encryption_key' => $b->device_encryption_key, 'capabilities' => $b->capabilities];
    }

    public function issue(string $account, string $root, stdClass $device, string $session, string $intent, string $generation, ?stdClass $head, string $binding): stdClass
    {
        if (DB::table('auth_challenges')->count() >= 50000) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        $id = P::b64(random_bytes(16));
        $context = (object) ['purpose' => 'device-possession-challenge', 'contract' => 'p02-state-c1', 'protocol' => 'anynote', 'protocol_version' => 1, 'service_id' => config('api.service_id'), 'account_id' => $account, 'root_fingerprint' => $root, 'intent' => $intent, 'challenge_id' => $id, 'session_binding' => Sessions::proofBinding($session), 'generation' => $generation, 'roster' => $head, 'nonce' => P::b64(random_bytes(32)), 'device' => $device, 'expires_at' => (string) (time() * 1000 + 60000)];
        $plain = (object) ['purpose' => 'device-encryption-proof', 'context' => $context, 'secret' => P::b64(random_bytes(32))];
        $this->contracts->value('state', 'challenge-plaintext', $plain);
        $challenge = (object) ['context' => $context, 'sealed_challenge' => P::b64(sodium_crypto_box_seal(P::canonical($plain), P::binary($device->encryption_key))), 'challenge_digest' => P::digest('p02-state-c1', 'challenge-plaintext', $plain)];
        $this->contracts->value('state', 'challenge', $challenge);
        DB::table('auth_challenges')->insert(['id' => $id, 'account_id' => $account, 'binding_hash' => $binding, 'purpose' => 'device', 'expires_at' => now()->addSeconds(60), 'data' => P::canonical($challenge)]);
        sodium_memzero($plain->secret);

        return $challenge;
    }

    public function validate(stdClass $challenge, stdClass $proof, string $session): void
    {
        $this->contracts->value('state', 'possession', $proof);
        $c = $challenge->context;
        $b = $proof->body;
        foreach (['service_id', 'account_id', 'root_fingerprint'] as $field) {
            if ($b->$field !== $c->$field) {
                throw new ApiException('AUTH_REQUIRED');
            }
        }
        if ($c->session_binding !== Sessions::proofBinding($session) || $b->session_binding !== $c->session_binding || $b->device_id !== $c->device->device_id || $b->challenge_digest !== P::digest('p02-state-c1', 'challenge', $challenge) || (int) $c->expires_at <= time() * 1000) {
            throw new ApiException('AUTH_REQUIRED');
        }
        P::verify('p02-state-c1', 'device-possession-proof', $b, $proof->signature, $c->device->signing_key);
        $plain = (object) ['purpose' => 'device-encryption-proof', 'context' => $c, 'secret' => $b->challenge_response];
        if (! hash_equals($challenge->challenge_digest, P::digest('p02-state-c1', 'challenge-plaintext', $plain))) {
            throw new ApiException('AUTH_REQUIRED');
        }
    }

    public function challenge(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $s = $this->sessions->current($r, true);
            [$identity, $row, $certificate] = $this->authorization->certifiedDevice($s->account_id, $id);
            if ($s->device_commitment !== null && ! hash_equals($s->device_commitment, self::commitment(self::device($certificate)))) {
                throw new ApiException('AUTH_REQUIRED');
            }
            if (DB::table('auth_challenges')->where('account_id', $s->account_id)->where('purpose', 'device')->whereNull('consumed_at')->where('expires_at', '>', now())->count() >= 10) {
                throw new ApiException('RESOURCE_LIMIT');
            }
            $c = $this->issue($s->account_id, $identity->root_fingerprint, self::device($certificate), $s->id, 'device-proof', (string) $identity->recovery_generation, (object) ['version' => (string) $identity->roster_sequence, 'digest' => $identity->roster_digest], hash('sha256', $s->id));

            return ['version' => 1, 'challenge' => $c];
        }, 3);
    }

    public function upgrade(Request $r, stdClass $body): array
    {
        $result = DB::transaction(function () use ($r, $body) {
            $s = $this->sessions->current($r, true);
            $ch = DB::table('auth_challenges')->where('id', $body->challenge_id)->lockForUpdate()->first();
            if (! $ch || $ch->purpose !== 'device' || $ch->account_id !== $s->account_id || $ch->binding_hash !== hash('sha256', $s->id) || $ch->consumed_at !== null || $ch->expires_at <= now()->format('Y-m-d H:i:s')) {
                return new ApiException('AUTH_REQUIRED');
            }
            DB::table('auth_challenges')->where('id', $ch->id)->update(['consumed_at' => now()]);
            try {
                $c = json_decode($ch->data);
                [$identity, $device, $cert] = $this->authorization->certifiedDevice($s->account_id, $c->context->device->device_id);
                if ($c->context->generation !== (string) $identity->recovery_generation || $c->context->roster->digest !== $identity->roster_digest || P::canonical($c->context->device) !== P::canonical(self::device($cert)) || ($s->device_commitment !== null && $s->device_commitment !== self::commitment(self::device($cert)))) {
                    throw new ApiException('AUTH_REQUIRED');
                }
                $this->validate($c, $body->proof, $s->id);
                DB::table('auth_sessions')->where('id', $s->id)->update(['state' => 'trusted', 'device_id' => $device->id, 'recovery_generation' => $identity->recovery_generation, 'device_commitment' => self::commitment(self::device($cert))]);

                return $this->sessions->result($r, DB::table('auth_sessions')->where('id', $s->id)->first());
            } catch (\Throwable $e) {
                return $e instanceof ApiException ? $e : new ApiException('AUTH_REQUIRED');
            }
        }, 3);
        if ($result instanceof ApiException) {
            throw $result;
        }

        return $result;
    }
}
