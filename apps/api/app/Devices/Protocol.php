<?php

namespace App\Devices;

use App\Auth\Contracts;
use App\Auth\Proof;
use App\Auth\Sessions;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Public verification only. P02 closed records and domains are unchanged. */
final class Protocol
{
    public function __construct(private Contracts $contracts, private Authorization $authorization, private Proof $proof) {}

    public static function require(bool $value, string $error = 'INVALID_SIGNATURE'): void
    {
        if (! $value) { throw new ApiException($error); }
    }

    public static function equal($a, $b): bool
    {
        return P::canonical((object) ['value' => $a]) === P::canonical((object) ['value' => $b]);
    }

    public static function head(stdClass $i): stdClass
    {
        return (object) ['version' => (string) $i->roster_sequence, 'digest' => $i->roster_digest];
    }

    public function scope(stdClass $i, stdClass $b, bool $current = true): void
    {
        self::require($b->service_id === config('api.service_id') && $b->account_id === $i->account_id && $b->root_fingerprint === $i->root_fingerprint);
        if ($current) { self::require($b->generation === (string) $i->recovery_generation && self::equal($b->roster, self::head($i)), 'ROSTER_CHANGED'); }
    }

    public function fresh(stdClass $i, stdClass $d, ?string $operation = null): void
    {
        $this->contracts->value('state', 'device', $d);
        $root = json_decode($i->identity_record)->body;
        self::require(! in_array($d->signing_key, [$root->root_signing_key, $root->recovery_encryption_key], true) && ! in_array($d->encryption_key, [$root->root_signing_key, $root->recovery_encryption_key], true));
        $ordered = $d->capabilities; sort($ordered, SORT_STRING);
        self::require($d->capabilities === $ordered && count($ordered) === count(array_unique($ordered)) && $d->signing_key !== $d->encryption_key);
        self::require(! DB::table('devices')->where('id', $d->device_id)->exists(), 'IDEMPOTENCY_MISMATCH');
        foreach (DB::table('devices')->where('account_id', $i->account_id)->get() as $old) {
            self::require(! in_array($d->signing_key, [$old->signing_key, $old->encryption_key], true) && ! in_array($d->encryption_key, [$old->signing_key, $old->encryption_key], true), 'IDEMPOTENCY_MISMATCH');
        }
        foreach (DB::table('enrollment_sessions')->where('account_id', $i->account_id)->whereNotNull('offer_record')->get() as $old) {
            if ($old->id === $operation) { continue; }
            $p = json_decode($old->offer_record)->body->device;
            self::require($p->device_id !== $d->device_id && ! in_array($d->signing_key, [$p->signing_key, $p->encryption_key], true) && ! in_array($d->encryption_key, [$p->signing_key, $p->encryption_key], true), 'IDEMPOTENCY_MISMATCH');
        }
    }

    public function window(string $expires, int $maximum = 600000): void
    {
        $remaining = (int) $expires - (int) floor(microtime(true) * 1000);
        self::require($remaining > 0 && $remaining <= $maximum, 'TRANSITION_EXPIRED');
    }

    public function approver(stdClass $i, stdClass $actor): stdClass
    {
        [, $row, $cert] = $this->authorization->certifiedDevice($i->account_id, $actor->device_id);
        self::require($row->certificate_digest === $actor->certificate_digest && in_array('delegate-device', $cert->body->capabilities, true));
        return $cert;
    }

    public function invitation(stdClass $i, stdClass $record): stdClass
    {
        $this->contracts->value('state', 'invitation', $record); $b = $record->body;
        $this->scope($i, $b); $this->window($b->expires_at);
        $cert = $this->approver($i, $b->approver);
        P::verify('p02-state-c1', $b->purpose, $b, $record->signature, $cert->body->device_signing_key);
        return $cert;
    }

    public function offer(stdClass $i, stdClass $record, string $session, ?stdClass $invitation, ?string $operation = null): void
    {
        $this->contracts->value('state', 'offer', $record); $b = $record->body;
        $this->scope($i, $b); $this->window($b->expires_at); $this->fresh($i, $b->device, $operation);
        self::require($b->session_binding === Sessions::proofBinding($session), 'AUTH_REQUIRED');
        if ($invitation) {
            $this->invitation($i, $invitation);
            self::require($b->operation_id === $invitation->body->operation_id && $b->expires_at === $invitation->body->expires_at && $b->invitation_digest === P::digest('p02-state-c1', 'invitation', $invitation));
        } else { self::require($b->invitation_digest === null); }
        P::verify('p02-state-c1', $b->purpose, $b, $record->signature, $b->device->signing_key);
    }

    private function certificate(stdClass $i, stdClass $cert, stdClass $device, string $generation, stdClass $issuer, string $transcript, string $key): void
    {
        $this->contracts->value('identity', 'certificate', $cert);
        $expected = (object) ['purpose' => 'provisional-device-certificate', 'contract' => 'p02-identity-c1', 'protocol' => 'anynote', 'protocol_version' => 1, 'service_id' => config('api.service_id'), 'account_id' => $i->account_id, 'root_fingerprint' => $i->root_fingerprint, 'recovery_generation' => $generation, 'predecessor_roster' => self::head($i), 'issuer' => $issuer, 'device_id' => $device->device_id, 'device_signing_key' => $device->signing_key, 'device_encryption_key' => $device->encryption_key, 'capabilities' => $device->capabilities, 'pairing_transcript_digest' => $transcript];
        self::require(self::equal($cert->body, $expected));
        P::verify('p02-identity-c1', 'provisional-device-certificate', $cert->body, $cert->signature, $key);
    }

    public function approval(stdClass $i, stdClass $transcript, stdClass $approval, string $session): stdClass
    {
        $this->contracts->value('state', 'transcript', $transcript); $this->contracts->value('state', 'approval', $approval);
        $o = $transcript->offer->body; $r = $transcript->response->body; $a = $approval->body;
        $this->offer($i, $transcript->offer, $session, $transcript->invitation, $o->operation_id);
        $this->scope($i, $r); $this->scope($i, $a);
        $cert = $this->approver($i, $r->approver);
        self::require($r->operation_id === $o->operation_id && $r->offer_digest === P::digest('p02-state-c1', 'offer', $transcript->offer) && $r->invitation_digest === $o->invitation_digest && $r->expires_at === $o->expires_at);
        if ($transcript->invitation) { self::require(self::equal($transcript->invitation->body->approver, $r->approver)); }
        P::verify('p02-state-c1', $r->purpose, $r, $transcript->response->signature, $cert->body->device_signing_key);
        $digest = P::digest('p02-state-c1', 'transcript', $transcript);
        self::require($a->operation_id === $o->operation_id && $a->session_binding === $o->session_binding && $a->transcript_digest === $digest && $a->expires_at === $o->expires_at);
        self::require(array_diff($o->device->capabilities, $cert->body->capabilities) === []);
        $this->certificate($i, $a->certificate, $o->device, (string) $i->recovery_generation, (object) ['kind' => 'device', 'device_id' => $r->approver->device_id, 'certificate_digest' => $r->approver->certificate_digest], $digest, $cert->body->device_signing_key);
        P::verify('p02-state-c1', $a->purpose, $a, $approval->signature, $cert->body->device_signing_key);
        return $cert;
    }

    public function descendants(stdClass $i, array $targets): array
    {
        $rows = DB::table('devices')->where('account_id', $i->account_id)->where('status', 'active')->orderBy('id')->get();
        $active = $rows->pluck('id')->all(); self::require(array_diff($targets, $active) === [], 'NOT_FOUND');
        $affected = $targets;
        do {
            $before = count($affected);
            foreach ($rows as $d) {
                $cert = json_decode($d->certificate_record)->body;
                $parent = $cert->issuer->kind === 'device' ? $cert->issuer->device_id : null;
                self::require($d->parent_device_id === $parent);
                if (in_array($parent, $affected, true) && ! in_array($d->id, $affected, true)) { $affected[] = $d->id; }
            }
        } while ($before !== count($affected));
        sort($affected, SORT_STRING); return $affected;
    }

    public function event(stdClass $i, stdClass $event, string $kind): void
    {
        $this->contracts->value('state', 'event', $event); $b = $event->body;
        $this->scope($i, $b, false);
        self::require($b->kind === $kind && self::equal($b->predecessor, self::head($i)) && $b->version === (string) ($i->roster_sequence + 1) && $b->generation === (string) ($i->recovery_generation + ($kind === 'reset' ? 1 : 0)), 'ROSTER_CHANGED');
        self::require($i->roster_sequence < 999, 'RESOURCE_LIMIT');
    }

    public function confirmation(stdClass $i, stdClass $event, stdClass $pending, string $session): stdClass
    {
        $this->event($i, $event, 'enroll'); $b = $event->body; $p = $b->payload;
        self::require($b->operation_id === $pending->id && self::equal($p->transcript, json_decode($pending->transcript_record)) && self::equal($p->approval, json_decode($pending->approval_record)));
        $this->approval($i, $p->transcript, $p->approval, $session);
        $d = $p->transcript->offer->body->device; $c = $p->confirmation->body; $a = $p->approval->body;
        $this->scope($i, $c);
        self::require($c->operation_id === $b->operation_id && $c->session_binding === Sessions::proofBinding($session) && $c->transcript_digest === $a->transcript_digest && $c->certificate_digest === P::digest('p02-identity-c1', 'device-certificate', $a->certificate) && $c->approval_digest === P::digest('p02-state-c1', 'approval', $p->approval) && $b->signer === $d->device_id);
        $plain = (object) ['purpose' => 'pairing-encryption-proof', 'transcript_digest' => $a->transcript_digest, 'device_id' => $d->device_id, 'secret' => $c->challenge_response];
        self::require($a->challenge_digest === P::digest('p02-state-c1', 'pairing-proof-plaintext', $plain));
        P::verify('p02-state-c1', $c->purpose, $c, $p->confirmation->signature, $d->signing_key);
        P::verify('p02-state-c1', $b->purpose, $b, $event->signature, $d->signing_key);
        return $a->certificate;
    }

    public function reset(stdClass $i, stdClass $event, stdClass $stored, string $session): stdClass
    {
        $this->event($i, $event, 'reset'); $b = $event->body; $p = $b->payload;
        self::require(self::equal($p->challenge, json_decode($stored->data)) && $stored->binding_hash === hash('sha256', $session) && $stored->consumed_at === null && $stored->expires_at > now()->format('Y-m-d H:i:s'), 'AUTH_REQUIRED');
        $c = $p->challenge->context; $this->scope($i, $c); $this->window($c->expires_at, 60000);
        self::require($c->intent === 'reset' && $b->signer === 'root' && $p->active_device_limit === (string) $i->device_limit);
        $this->fresh($i, $c->device);
        $this->proof->validate($p->challenge, $p->confirmation, $session);
        $root = json_decode($i->identity_record)->body->root_signing_key;
        $this->certificate($i, $p->certificate, $c->device, $b->generation, (object) ['kind' => 'root', 'root_fingerprint' => $i->root_fingerprint], P::digest('p02-state-c1', 'challenge', $p->challenge), $root);
        P::verify('p02-state-c1', $b->purpose, $b, $event->signature, $root);
        return $p->certificate;
    }
}
