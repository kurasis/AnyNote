<?php

namespace App\Devices;

use App\Auth\Sessions;
use App\Backend\Authorization;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Http\Controllers\DevicesController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Same-account extension of existing access; no membership/role or content-write privilege. */
final class Envelopes
{
    public function __construct(private Sessions $sessions, private Authorization $authorization, private SyncWriter $sync) {}

    public function publish(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $s = $this->sessions->current($r, true);
            $actor = $this->authorization->actor($this->sessions->secret($r));
            [$i, $device, $certificate] = $this->authorization->certifiedDevice($s->account_id, $s->device_id);
            Protocol::require(count($body->records) > 0 && in_array('distribute-group-key', $certificate->body->capabilities, true), 'ROLE_FORBIDDEN');
            $sender = Settings::sender($i, $device);
            $groups = [];
            $seen = [];
            foreach ($body->records as $record) {
                $c = $record->body->context;
                $target = $c->recipient;
                Protocol::require($target->kind === 'device' && $target->account_id === $s->account_id, 'ROLE_FORBIDDEN');
                [, $row, $cert] = $this->authorization->certifiedDevice($s->account_id, $target->device_id);
                Protocol::require(in_array('receive-group-key', $cert->body->capabilities, true) && Protocol::equal($target, Settings::recipient($i, $row)), 'ROSTER_CHANGED');
                Protocol::require($c->service_id === config('api.service_id') && Protocol::equal($c->issuer, $sender));
                P::verify('p02-identity-c1', 'group-key-distribution', $record->body, $record->signature, $certificate->body->device_signing_key);
                $unique = $c->group_id.'/'.$c->key_epoch.'/'.$target->device_id;
                Protocol::require(! isset($seen[$unique]), 'INVALID_REQUEST');
                $seen[$unique] = true;
                $groups[$c->group_id] = true;
            }
            ksort($groups, SORT_STRING);
            foreach (array_keys($groups) as $id) {
                $groups[$id] = $this->authorization->group($actor, $id);
            }
            $bytes = 0;
            $new = [];
            $events = [];
            foreach ($body->records as $record) {
                $c = $record->body->context;
                $g = $groups[$c->group_id];
                Protocol::require(Protocol::equal($c->membership_head, (object) ['version' => (string) $g->policy_sequence, 'digest' => $g->policy_digest]), 'POLICY_CHANGED');
                $epoch = DB::table('group_key_epochs')->where('group_id', $g->id)->where('epoch_number', $c->key_epoch)->first();
                Protocol::require($epoch !== null && $epoch->digest === $c->epoch_digest, 'REKEY_REQUIRED');
                $prior = DB::table('key_envelopes')->where('group_id', $g->id)->where('epoch_number', $c->key_epoch)->where('recipient_account_id', $s->account_id)->where('recipient_kind', 'device')->where('recipient_key_fingerprint', $c->recipient->encryption_key_fingerprint)->get();
                $exists = false;
                foreach ($prior as $item) {
                    $old = json_decode($item->signed_record);
                    if ($old->body->context->recipient->device_id === $c->recipient->device_id) {
                        Protocol::require(Protocol::equal($old, $record), 'IDEMPOTENCY_MISMATCH');
                        $exists = true;
                    }
                }
                if (! $exists) {
                    $new[] = $record;
                    $bytes += strlen(P::binary($record->body->sealed_ciphertext));
                }
            }
            // Security reserve admission is reachable only after all exact maintenance predicates.
            // No ordinary object/upload can select it. At most 60 bounded sealed grants per call.
            $reserve = DB::table('quota_ledgers')->where('scope', 'security')->lockForUpdate()->first();
            Protocol::require($reserve !== null && $bytes <= 245760 && $bytes <= (int) $reserve->limit_bytes - (int) $reserve->committed_bytes - (int) $reserve->reserved_bytes, 'INSUFFICIENT_STORAGE');
            if ($new !== []) {
                DB::table('quota_ledgers')->where('scope', 'security')->increment('committed_bytes', $bytes);
                DB::table('quota_movements')->insert(['id' => P::b64(random_bytes(16)), 'scope' => 'security', 'committed_delta' => $bytes, 'reserved_delta' => 0]);
                foreach ($new as $record) {
                    Settings::envelope($record);
                    $c = $record->body->context;
                    $events[] = ['group_id' => $c->group_id, 'audience_account_id' => $s->account_id, 'kind' => 'device-key-envelope', 'object_id' => $c->recipient->device_id, 'revision_id' => null, 'digest' => P::digest('p02-identity-c1', 'group-key-distribution', $record)];
                }
                $this->sync->append($events);
            }

            return ['version' => 1, 'status' => 'ok'];
        }, 3);
    }

    public function read(Request $r, bool $recovery): array
    {
        return DB::transaction(function () use ($r, $recovery) {
            $s = $this->sessions->current($r, true);
            $this->authorization->actor($this->sessions->secret($r));
            [$i, $device] = $this->authorization->certifiedDevice($s->account_id, $s->device_id);
            $q = DevicesController::query($r, ['after']);
            Protocol::require(! isset($q['after']) || P::isBinary($q['after'], 16), 'INVALID_REQUEST');
            $key = $recovery ? json_decode($i->identity_record)->body->recovery_encryption_key : $device->encryption_key;
            $rows = DB::table('key_envelopes as e')->join('group_memberships as m', function ($j) {
                $j->on('e.group_id', '=', 'm.group_id')->on('e.recipient_account_id', '=', 'm.account_id');
            })->join('groups as g', 'g.id', '=', 'e.group_id')->where('e.recipient_account_id', $s->account_id)->where('e.recipient_kind', $recovery ? 'account-recovery' : 'device')->where('e.recipient_key_fingerprint', Settings::keyFingerprint($key))->where('m.status', 'active')->where('g.state', '!=', 'purged')->where(function ($q) use ($s) {
                $q->where('g.kind', 'shared')->orWhere(function ($q) use ($s) {
                    $q->where('g.kind', 'private')->where('g.owner_account_id', $s->account_id)->where('m.role', 'owner');
                });
            })->when(isset($q['after']), fn ($query) => $query->where('e.id', '>', $q['after']))->orderBy('e.id')->limit(61)->select('e.id', 'e.signed_record')->get();
            $result = [];
            $last = null;
            $bytes = 0;
            foreach ($rows->take(60) as $row) {
                if ($bytes + strlen($row->signed_record) > 196608 && $result !== []) {
                    break;
                }
                $record = json_decode($row->signed_record);
                $recipient = $record->body->context->recipient;
                Protocol::require($recipient->root_fingerprint === $i->root_fingerprint && ($recovery || ($recipient->device_id === $s->device_id && $recipient->recovery_generation === (string) $i->recovery_generation)), 'INVALID_SIGNATURE');
                $result[] = $record;
                $last = $row->id;
                $bytes += strlen($row->signed_record);
            }

            return ['version' => 1, 'records' => $result, 'next' => count($result) < $rows->count() ? $last : null];
        }, 3);
    }
}
