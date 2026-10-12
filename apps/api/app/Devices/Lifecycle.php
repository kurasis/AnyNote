<?php

namespace App\Devices;

use App\Auth\Proof;
use App\Auth\Sessions;
use App\Backend\Authorization;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** One account lock serializes pending approvals, roster CAS, recovery and session changes. */
final class Lifecycle
{
    public function __construct(private Sessions $sessions, private Authorization $authorization, private Protocol $protocol, private Proof $proof, private SyncWriter $sync) {}

    private function context(Request $r, bool $trusted = false): array
    {
        $s = $this->sessions->current($r, true);
        $i = DB::table('account_identities')->where('account_id', $s->account_id)->lockForUpdate()->first();
        Protocol::require($i !== null, 'AUTH_REQUIRED');
        if ($trusted) {
            $this->authorization->actor($this->sessions->secret($r));
        }

        return [$s, $i];
    }

    private function pending(stdClass $s, string $id, bool $live = true): stdClass
    {
        $p = DB::table('enrollment_sessions')->where('account_id', $s->account_id)->where('id', $id)->lockForUpdate()->first();
        Protocol::require($p !== null, 'NOT_FOUND');
        if ($live) {
            Protocol::require(in_array($p->state, ['pending', 'approved'], true) && $p->expires_at > now()->format('Y-m-d H:i:s'), 'ENROLLMENT_EXPIRED');
        }

        return $p;
    }

    private function result(stdClass $p): array
    {
        return ['version' => 1, 'operation_id' => $p->id, 'state' => $p->state, 'expires_at' => (string) (strtotime($p->expires_at.' UTC') * 1000)];
    }

    public function create(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            [$s, $i] = $this->context($r, $body->mode === 'existing-device-invitation');
            $record = $body->record;
            $id = $record->body->operation_id;
            if ($body->mode === 'new-device-offer') {
                Protocol::require($s->state === 'restricted', 'ROLE_FORBIDDEN');
                $this->protocol->offer($i, $record, $s->id, null, $id);
                Protocol::require($s->device_commitment === null || $s->device_commitment === Proof::commitment($record->body->device), 'AUTH_REQUIRED');
            } else {
                Sessions::recent($s);
                $this->protocol->invitation($i, $record);
                Protocol::require($record->body->approver->device_id === $s->device_id, 'ROLE_FORBIDDEN');
            }
            $prior = DB::table('enrollment_sessions')->where('id', $id)->first();
            if ($prior) {
                Protocol::require($prior->account_id === $s->account_id && $prior->creator_session_id === $s->id && $prior->mode === $body->mode && Protocol::equal(json_decode($prior->public_record), $record), 'IDEMPOTENCY_MISMATCH');

                return $this->result($prior);
            }
            Protocol::require(DB::table('enrollment_sessions')->count() < 50000 && DB::table('enrollment_sessions')->where('account_id', $s->account_id)->count() < 4096, 'RESOURCE_LIMIT');
            Protocol::require(DB::table('enrollment_sessions')->where('account_id', $s->account_id)->whereIn('state', ['pending', 'approved'])->where('expires_at', '>', now())->count() < 32, 'RESOURCE_LIMIT');
            Protocol::require(! DB::table('enrollment_sessions')->where('new_session_id', $s->id)->exists(), 'IDEMPOTENCY_MISMATCH');
            DB::table('enrollment_sessions')->insert(['id' => $id, 'account_id' => $s->account_id, 'commitment' => P::digest('p02-state-c1', $body->mode === 'new-device-offer' ? 'offer' : 'invitation', $record), 'state' => 'pending', 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil((int) $record->body->expires_at / 1000)), 'creator_session_id' => $s->id, 'new_session_id' => $body->mode === 'new-device-offer' ? $s->id : null, 'new_device_id' => $body->mode === 'new-device-offer' ? $record->body->device->device_id : null, 'approver_device_id' => $body->mode === 'existing-device-invitation' ? $s->device_id : null, 'mode' => $body->mode, 'public_record' => P::canonical($record), 'offer_record' => $body->mode === 'new-device-offer' ? P::canonical($record) : null]);

            return $this->result($this->pending($s, $id));
        }, 3);
    }

    private function frame(stdClass $pending, stdClass $frame): void
    {
        $message = $frame->context->message;
        $existing = DB::table('device_relay_frames')->where('enrollment_id', $pending->id)->where('message', $message)->first();
        if ($existing) {
            Protocol::require(Protocol::equal(json_decode($existing->frame), $frame), 'IDEMPOTENCY_MISMATCH');

            return;
        }
        DB::table('device_relay_frames')->insert(['enrollment_id' => $pending->id, 'message' => $message, 'frame' => P::canonical($frame)]);
    }

    public function relay(Request $r, string $id, ?stdClass $body): array
    {
        return DB::transaction(function () use ($r, $id, $body) {
            [$s, $i] = $this->context($r);
            $p = $this->pending($s, $id, $body !== null);
            if ($body) {
                $m = $body->frame->context->message;
                if ($m === 'new-device-offer') {
                    Protocol::require($s->state === 'restricted' && $body->offer !== null && $p->mode === 'existing-device-invitation' && $p->state === 'pending', 'ROLE_FORBIDDEN');
                    Protocol::require($p->new_session_id === null || $p->new_session_id === $s->id, 'ROLE_FORBIDDEN');
                    Protocol::require(! DB::table('enrollment_sessions')->where('new_session_id', $s->id)->where('id', '!=', $id)->exists(), 'IDEMPOTENCY_MISMATCH');
                    $invitation = json_decode($p->public_record);
                    $this->protocol->offer($i, $body->offer, $s->id, $invitation, $id);
                    Protocol::require($s->device_commitment === null || $s->device_commitment === Proof::commitment($body->offer->body->device), 'AUTH_REQUIRED');
                    Protocol::require($body->frame->context->anchor_digest === $p->commitment);
                    if ($p->offer_record) {
                        Protocol::require(Protocol::equal(json_decode($p->offer_record), $body->offer), 'IDEMPOTENCY_MISMATCH');
                    }
                    DB::table('enrollment_sessions')->where('id', $id)->update(['new_session_id' => $s->id, 'new_device_id' => $body->offer->body->device->device_id, 'offer_record' => P::canonical($body->offer)]);
                } elseif ($m === 'approver-response') {
                    $this->authorization->actor($this->sessions->secret($r));
                    Sessions::recent($s);
                    Protocol::require($body->offer === null && $p->state === 'pending' && $p->offer_record !== null && ($p->approver_device_id === null || $p->approver_device_id === $s->device_id), 'ROLE_FORBIDDEN');
                    $offer = json_decode($p->offer_record);
                    $this->protocol->scope($i, $offer->body);
                    $this->protocol->window($offer->body->expires_at);
                    Protocol::require($body->frame->context->anchor_digest === P::digest('p02-state-c1', 'offer', $offer));
                    DB::table('enrollment_sessions')->where('id', $id)->update(['approver_device_id' => $s->device_id]);
                } elseif ($m === 'new-device-confirmation') {
                    Protocol::require($body->offer === null && $p->state === 'approved' && $p->new_session_id === $s->id && $body->frame->context->anchor_digest === P::digest('p02-state-c1', 'transcript', json_decode($p->transcript_record)), 'ROLE_FORBIDDEN');
                } else {
                    throw new ApiException('ROLE_FORBIDDEN');
                }
                $this->frame($p, $body->frame);
                $p = $this->pending($s, $id);
            } else {
                Protocol::require($s->id === $p->creator_session_id || $s->id === $p->new_session_id || $s->state === 'trusted', 'ROLE_FORBIDDEN');
                if (in_array($p->state, ['pending', 'approved'], true) && $p->expires_at <= now()->format('Y-m-d H:i:s')) {
                    DB::table('enrollment_sessions')->where('id', $id)->update(['state' => 'expired']);
                    $p->state = 'expired';
                }
            }

            return ['version' => 1, 'operation_id' => $id, 'state' => $p->state, 'frames' => DB::table('device_relay_frames')->where('enrollment_id', $id)->orderBy('message')->get()->map(fn ($f) => json_decode($f->frame))->all(), 'event' => $p->event_record ? json_decode($p->event_record) : null];
        }, 3);
    }

    public function approve(Request $r, string $id, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $id, $body) {
            [$s, $i] = $this->context($r, true);
            Sessions::recent($s);
            $p = $this->pending($s, $id);
            Protocol::require($p->approver_device_id === $s->device_id && $p->new_session_id !== null && $body->transcript->offer->body->operation_id === $id && Protocol::equal($body->transcript->offer, json_decode($p->offer_record)) && (($p->mode === 'new-device-offer' && $body->transcript->invitation === null) || ($p->mode === 'existing-device-invitation' && Protocol::equal($body->transcript->invitation, json_decode($p->public_record)))), 'ROLE_FORBIDDEN');
            $this->protocol->approval($i, $body->transcript, $body->approval, $p->new_session_id);
            Protocol::require($body->transcript->response->body->approver->device_id === $s->device_id);
            Protocol::require($body->frame->context->message === 'approver-approval' && $body->frame->context->anchor_digest === $body->approval->body->transcript_digest);
            if ($p->state === 'approved') {
                Protocol::require(Protocol::equal(json_decode($p->transcript_record), $body->transcript) && Protocol::equal(json_decode($p->approval_record), $body->approval), 'IDEMPOTENCY_MISMATCH');
            }
            Protocol::require(DB::table('devices')->where('account_id', $s->account_id)->where('status', 'active')->count() < (int) $i->device_limit, 'RESOURCE_LIMIT');
            DB::table('enrollment_sessions')->where('id', $id)->update(['state' => 'approved', 'transcript_record' => P::canonical($body->transcript), 'approval_record' => P::canonical($body->approval)]);
            $this->frame($p, $body->frame);

            return $this->result($this->pending($s, $id));
        }, 3);
    }

    public function cancel(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            [$s] = $this->context($r);
            $p = $this->pending($s, $id, false);
            Protocol::require($s->id === $p->creator_session_id || $s->id === $p->new_session_id || ($s->state === 'trusted' && $s->device_id === $p->approver_device_id), 'ROLE_FORBIDDEN');
            Protocol::require($p->state !== 'confirmed', 'IDEMPOTENCY_MISMATCH');
            DB::table('enrollment_sessions')->where('id', $id)->update(['state' => 'cancelled']);
            DB::table('device_relay_frames')->where('enrollment_id', $id)->delete();

            return ['version' => 1, 'status' => 'ok'];
        }, 3);
    }

    private function receipt(stdClass $s, stdClass $event): ?array
    {
        $row = DB::table('device_transition_receipts')->where('operation_id', $event->body->operation_id)->first();
        if (! $row) {
            return null;
        }
        Protocol::require($row->account_id === $s->account_id && $row->session_id === $s->id && $row->request_digest === P::digest('p02-state-c1', 'event', $event), 'IDEMPOTENCY_MISMATCH');

        return ['version' => 1, 'session' => Sessions::public($s), 'receipt' => json_decode($row->result)];
    }

    private function commit(stdClass $s, stdClass $i, stdClass $event, ?stdClass $certificate, array $revoked): array
    {
        $b = $event->body;
        Protocol::require((int) $b->version < 1000, 'RESOURCE_LIMIT');
        $digest = P::digest('p02-state-c1', 'event', $event);
        $active = $certificate?->body->device_id;
        if ($certificate) {
            $c = $certificate->body;
            DB::table('devices')->insert(['id' => $c->device_id, 'account_id' => $s->account_id, 'signing_key' => $c->device_signing_key, 'encryption_key' => $c->device_encryption_key, 'certificate_digest' => P::digest('p02-identity-c1', 'device-certificate', $certificate), 'certificate_record' => P::canonical($certificate), 'recovery_generation' => $b->generation, 'status' => 'active', 'can_sign_content' => in_array('sign-content', $c->capabilities, true), 'parent_device_id' => $c->issuer->kind === 'device' ? $c->issuer->device_id : null, 'platform' => $s->transport === 'native' ? 'windows' : 'pwa']);
        }
        DB::table('devices')->where('account_id', $s->account_id)->whereIn('id', $revoked)->update(['status' => 'revoked']);
        $sessions = DB::table('auth_sessions')->where('account_id', $s->account_id)->where('state', '!=', 'revoked')->orderBy('id')->lockForUpdate()->get();
        $commitments = DB::table('devices')->where('account_id', $s->account_id)->whereIn('id', $revoked)->get()->map(fn ($d) => P::b64(hash('sha256', "AnyNote/P06/device-key-commitment\0".P::binary($d->signing_key).P::binary($d->encryption_key), true)))->all();
        $derived = [];
        foreach (DB::table('native_authorizations')->where('account_id', $s->account_id)->get() as $a) {
            $data = json_decode($a->data);
            if ($b->kind === 'reset' || in_array($data->authorizing_device_id ?? null, $revoked, true)) {
                if (isset($data->session_id)) {
                    $derived[] = $data->session_id;
                }
                DB::table('native_authorizations')->where('id', $a->id)->update(['consumed_at' => now(), 'expires_at' => now()]);
            }
        }
        foreach ($sessions as $other) {
            if ($other->id !== $s->id && ($b->kind === 'reset' || in_array($other->device_id, $revoked, true) || in_array($other->device_commitment, $commitments, true) || ($other->state === 'restricted' && in_array($other->id, $derived, true)))) {
                Sessions::revoke($other->id);
            }
        }
        if ($active) {
            DB::table('auth_sessions')->where('id', $s->id)->update(['state' => 'trusted', 'device_id' => $active, 'recovery_generation' => $b->generation, 'device_commitment' => Proof::commitment(Proof::device($certificate))]);
        }
        DB::table('enrollment_sessions')->where('account_id', $s->account_id)->whereIn('state', ['pending', 'approved'])->where('id', '!=', $b->operation_id)->update(['state' => 'cancelled']);
        // Bound group locks follow account/device/session locks; sync counter is LAST.
        $groups = DB::table('group_memberships')->where('account_id', $s->account_id)->where('status', 'active')->orderBy('group_id')->pluck('group_id')->all();
        Protocol::require(count($groups) <= 1000, 'RESOURCE_LIMIT');
        if ($revoked !== []) {
            foreach ($groups as $id) {
                DB::table('groups')->where('id', $id)->lockForUpdate()->first();
                DB::table('groups')->where('id', $id)->update(['rekey_required' => true, 'history_closure_required' => true]);
            }
        }
        DB::table('account_identities')->where('account_id', $s->account_id)->update(['recovery_generation' => $b->generation, 'roster_sequence' => $b->version, 'roster_digest' => $digest]);
        DB::table('account_roster_events')->insert(['id' => $b->operation_id, 'account_id' => $s->account_id, 'sequence' => $b->version, 'parent_digest' => $i->roster_digest, 'digest' => $digest, 'signed_record' => P::canonical($event)]);
        DB::table('account_security_notifications')->insert(['id' => P::b64(random_bytes(16)), 'account_id' => $s->account_id, 'kind' => ['enroll' => 'device-enrolled', 'revoke' => 'device-revoked', 'reset' => 'recovery-reset'][$b->kind]]);
        $result = (object) ['version' => 1, 'operation_id' => $b->operation_id, 'event_digest' => $digest, 'head' => (object) ['version' => $b->version, 'digest' => $digest], 'generation' => $b->generation, 'activated_device_id' => $active, 'revoked_device_ids' => $revoked];
        DB::table('device_transition_receipts')->insert(['operation_id' => $b->operation_id, 'account_id' => $s->account_id, 'session_id' => $s->id, 'request_digest' => $digest, 'result' => P::canonical($result), 'expires_at' => now()->addDays(30)]);
        $this->sync->append([['audience_account_id' => $s->account_id, 'group_id' => null, 'kind' => 'device-roster', 'object_id' => $active ?? $s->account_id, 'revision_id' => null, 'digest' => $digest]]);
        // No business locks after SyncWriter.
        $s->state = $active ? 'trusted' : $s->state;
        $s->device_id = $active ?? $s->device_id;
        $s->recovery_generation = $b->generation;

        return ['version' => 1, 'session' => Sessions::public($s), 'receipt' => $result];
    }

    public function confirm(Request $r, string $id, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $id, $body) {
            [$s, $i] = $this->context($r);
            $cached = $this->receipt($s, $body->event);
            if ($cached) {
                return $cached;
            }
            Protocol::require($s->state === 'restricted' && $body->event->body->operation_id === $id, 'ROLE_FORBIDDEN');
            $p = $this->pending($s, $id);
            Protocol::require($p->state === 'approved' && $p->new_session_id === $s->id, 'ROLE_FORBIDDEN');
            $cert = $this->protocol->confirmation($i, $body->event, $p, $s->id);
            Protocol::require(DB::table('devices')->where('account_id', $s->account_id)->where('status', 'active')->count() < (int) $i->device_limit, 'RESOURCE_LIMIT');
            DB::table('enrollment_sessions')->where('id', $id)->update(['state' => 'confirmed', 'event_record' => P::canonical($body->event)]);

            return $this->commit($s, $i, $body->event, $cert, []);
        }, 3);
    }

    public function revoke(Request $r, string $id, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $id, $body) {
            [$s, $i] = $this->context($r, true);
            $cached = $this->receipt($s, $body->event);
            if ($cached) {
                return $cached;
            } Sessions::recent($s);
            $event = $body->event;
            $this->protocol->event($i, $event, 'revoke');
            Protocol::require($event->body->signer === $s->device_id && in_array($id, $event->body->payload->targets, true), 'ROLE_FORBIDDEN');
            $ordered = $event->body->payload->targets;
            sort($ordered, SORT_STRING);
            Protocol::require($ordered === $event->body->payload->targets && count(array_unique($ordered)) === count($ordered));
            $revoked = $this->protocol->descendants($i, $ordered);
            Protocol::require($revoked === $event->body->payload->affected_devices && ! in_array($s->device_id, $revoked, true), 'ROLE_FORBIDDEN');
            [, , $cert] = $this->authorization->certifiedDevice($s->account_id, $s->device_id);
            Protocol::require(in_array('delegate-device', $cert->body->capabilities, true));
            P::verify('p02-state-c1', $event->body->purpose, $event->body, $event->signature, $cert->body->device_signing_key);

            return $this->commit($s, $i, $event, null, $revoked);
        }, 3);
    }

    public function challenge(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            [$s, $i] = $this->context($r);
            Sessions::recent($s);
            Protocol::require($s->state === 'restricted', 'ROLE_FORBIDDEN');
            $this->protocol->fresh($i, $body->device);
            Protocol::require($s->device_commitment === null || $s->device_commitment === Proof::commitment($body->device), 'AUTH_REQUIRED');
            Protocol::require(DB::table('auth_challenges')->where('account_id', $s->account_id)->where('purpose', 'device')->whereNull('consumed_at')->where('expires_at', '>', now())->count() < 10, 'RESOURCE_LIMIT');

            return ['version' => 1, 'challenge' => $this->proof->issue($s->account_id, $i->root_fingerprint, $body->device, $s->id, 'reset', (string) $i->recovery_generation, Protocol::head($i), hash('sha256', $s->id))];
        }, 3);
    }

    public function reset(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            [$s, $i] = $this->context($r);
            $cached = $this->receipt($s, $body->event);
            if ($cached) {
                return $cached;
            } Sessions::recent($s);
            Protocol::require($s->state === 'restricted', 'ROLE_FORBIDDEN');
            $event = $body->event;
            Protocol::require($event->body->kind === 'reset', 'INVALID_REQUEST');
            $row = DB::table('auth_challenges')->where('id', $event->body->payload->challenge->context->challenge_id)->where('account_id', $s->account_id)->where('purpose', 'device')->lockForUpdate()->first();
            Protocol::require($row !== null, 'AUTH_REQUIRED');
            $cert = $this->protocol->reset($i, $event, $row, $s->id);
            $revoked = DB::table('devices')->where('account_id', $s->account_id)->where('status', 'active')->orderBy('id')->pluck('id')->all();
            DB::table('auth_challenges')->where('id', $row->id)->update(['consumed_at' => now()]);

            return $this->commit($s, $i, $event, $cert, $revoked);
        }, 3);
    }
}
