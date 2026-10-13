<?php

namespace App\Devices;

use App\Auth\Contracts;
use App\Auth\Sessions;
use App\Backend\Authorization;
use App\Backend\QuotaLedger;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;
use Truschery\Kanon\Json;

/** Exact one-account private genesis subset. General shared-group transitions remain P10. */
final class Settings
{
    public function __construct(private Sessions $sessions, private Contracts $contracts, private Authorization $authorization, private Protocol $protocol, private QuotaLedger $quota, private SyncWriter $sync) {}

    public static function keyFingerprint(string $key): string
    {
        return P::b64(hash('sha256', "AnyNote/p02-identity-c1/hash/x25519-public-key\0".P::binary($key), true));
    }

    public static function sender(stdClass $i, stdClass $d): stdClass
    {
        return (object) ['account_id' => $i->account_id, 'device_id' => $d->id, 'root_fingerprint' => $i->root_fingerprint, 'recovery_generation' => (string) $i->recovery_generation, 'roster_head' => Protocol::head($i), 'certificate_digest' => $d->certificate_digest];
    }

    public static function recipient(stdClass $i, ?stdClass $device): stdClass
    {
        $r = (object) ['kind' => $device ? 'device' : 'account-recovery', 'account_id' => $i->account_id, 'root_fingerprint' => $i->root_fingerprint, 'recovery_generation' => (string) $i->recovery_generation, 'roster_head' => Protocol::head($i)];
        if ($device) {
            $r->device_id = $device->id;
            $r->certificate_digest = $device->certificate_digest;
        }
        $r->encryption_key_fingerprint = self::keyFingerprint($device?->encryption_key ?? json_decode($i->identity_record)->body->recovery_encryption_key);

        return $r;
    }

    public static function envelope(stdClass $record): void
    {
        $c = $record->body->context;
        DB::table('key_envelopes')->insert(['id' => P::b64(random_bytes(16)), 'group_id' => $c->group_id, 'epoch_number' => $c->key_epoch, 'recipient_account_id' => $c->recipient->account_id, 'recipient_kind' => $c->recipient->kind, 'recipient_key_fingerprint' => $c->recipient->encryption_key_fingerprint, 'signed_record' => P::canonical($record), 'ciphertext_bytes' => strlen(P::binary($record->body->sealed_ciphertext))]);
    }

    public function create(Request $r, stdClass $body, bool $settings = true, string $kind = 'private'): array
    {
        return DB::transaction(function () use ($r, $body, $settings, $kind) {
            Protocol::require(in_array($kind, ['private', 'shared'], true) && (! $settings || $kind === 'private'), 'INVALID_REQUEST');
            $s = $this->sessions->current($r, true);
            $this->authorization->actor($this->sessions->secret($r));
            $hash = P::b64(hash('sha256', P::canonical($body), true));
            $old = $settings ? DB::table('account_settings_genesis')->where('account_id', $s->account_id)->first() : DB::table($kind === 'shared' ? 'shared_group_geneses' : 'private_group_geneses')->where('group_id', $body->commit->body->group_id)->first();
            if ($old) {
                Protocol::require(($settings || ($old->account_id === $s->account_id && $old->device_id === $s->device_id)) && $hash === $old->request_digest, 'IDEMPOTENCY_MISMATCH');
                $this->authorization->group($this->authorization->actor($this->sessions->secret($r)), $old->group_id);

                return ['version' => 1, 'group_id' => $old->group_id, 'commit' => json_decode($old->commit_record), 'pages' => [json_decode($old->grant_page)]];
            }
            if (! $settings) {
                Protocol::require(DB::table('account_settings_genesis')->where('account_id', $s->account_id)->exists(), 'KEYS_PENDING');
                Protocol::require(DB::table('groups')->where('owner_account_id', $s->account_id)->where('kind', 'private')->count() < 100, 'RESOURCE_LIMIT');
                Protocol::require(! DB::table($kind === 'shared' ? 'shared_group_geneses' : 'private_group_geneses')->where('account_id', $s->account_id)->where('device_id', $s->device_id)->where('operation_id', $body->commit->body->operation_id)->exists() && ! DB::table('mutation_receipts')->where('account_id', $s->account_id)->where('device_id', $s->device_id)->where('operation_id', $body->commit->body->operation_id)->exists(), 'IDEMPOTENCY_MISMATCH');
            }
            Protocol::require(count($body->pages) === 1, 'INVALID_REQUEST');
            [$i, $device, $certificate] = $this->authorization->certifiedDevice($s->account_id, $s->device_id);
            $commit = $body->commit;
            $b = $commit->body;
            $policy = $b->policy;
            Protocol::require($policy !== null, 'INVALID_REQUEST');
            $p = $policy->body;
            $intent = $b->intent;
            $v = $intent->body;
            $descriptor = $b->descriptor;
            $d = $descriptor->body;
            $page = $body->pages[0];
            $sender = self::sender($i, $device);
            $key = $certificate->body->device_signing_key;
            Protocol::require(in_array('sign-content', $certificate->body->capabilities, true) && in_array('distribute-group-key', $certificate->body->capabilities, true));
            foreach ([$policy, $intent, $descriptor, $commit] as $record) {
                P::verify('p02-group-c2', $record->body->purpose, $record->body, $record->signature, $key);
                Protocol::require($record->body->service_id === config('api.service_id') && $record->body->group_id === $b->group_id && $record->body->operation_id === $b->operation_id);
            }
            Protocol::require(Protocol::equal($p->signer, $sender) && Protocol::equal($v->signer, $sender) && Protocol::equal($d->signer, $sender));
            Protocol::require($policy->cosignature === null && $p->action === 'genesis' && $p->payload->group_kind === $kind && $p->version === '0' && $p->predecessor === null && Protocol::equal($p->members, [(object) ['account_id' => $s->account_id, 'root_fingerprint' => $i->root_fingerprint, 'role' => 'owner']]));
            $membership = (object) ['version' => '0', 'digest' => P::digest('p02-group-c2', 'policy', $policy)];
            $epoch = P::digest('p02-group-c2', 'epoch-intent', $intent);
            Protocol::require($v->reason === 'genesis' && $v->previous_epoch === null && $v->next_epoch === '0' && $v->retained_epochs === [] && $v->history_checkpoint_digest === null && Protocol::equal($v->expected_policy, $membership) && Protocol::equal($v->membership, $membership) && Protocol::equal($d->membership, $membership));
            $this->protocol->window($v->expires_at);
            Protocol::require(Protocol::equal($v->rosters, [(object) ['account_id' => $s->account_id, 'root_fingerprint' => $i->root_fingerprint, 'recovery_generation' => (string) $i->recovery_generation, 'roster' => Protocol::head($i)]]), 'ROSTER_CHANGED');
            $devices = DB::table('devices')->where('account_id', $s->account_id)->where('status', 'active')->orderBy('id')->get();
            $expected = [];
            foreach ($devices as $item) {
                [, , $cert] = $this->authorization->certifiedDevice($s->account_id, $item->id);
                Protocol::require(in_array('receive-group-key', $cert->body->capabilities, true));
                $expected['device/'.$item->id] = self::recipient($i, $item);
            }
            $expected['account-recovery/'] = self::recipient($i, null);
            Protocol::require($page->service_id === config('api.service_id') && $page->group_id === $b->group_id && $page->operation_id === $b->operation_id && $page->page_index === '0' && count($page->records) === count($expected));
            $count = count($page->records);
            $bytes = 0;
            $last = null;
            foreach ($page->records as $record) {
                $ctx = $record->body->context;
                $recipient = $ctx->recipient;
                $rid = $recipient->kind.'/'.($recipient->device_id ?? '');
                $order = str_pad($ctx->key_epoch, 19, '0', STR_PAD_LEFT).'/'.$recipient->account_id.'/'.$recipient->kind.'/'.($recipient->device_id ?? '');
                Protocol::require($last === null || strcmp($last, $order) < 0);
                $last = $order;
                Protocol::require(isset($expected[$rid]) && Protocol::equal($recipient, $expected[$rid]));
                unset($expected[$rid]);
                Protocol::require($ctx->service_id === config('api.service_id') && $ctx->group_id === $b->group_id && $ctx->key_epoch === '0' && $ctx->epoch_digest === $epoch && Protocol::equal($ctx->membership_head, $membership) && $ctx->operation_id === $b->operation_id && Protocol::equal($ctx->issuer, $sender));
                P::verify('p02-identity-c1', 'group-key-distribution', $record->body, $record->signature, $key);
                $bytes += strlen(P::binary($record->body->sealed_ciphertext));
            }
            Protocol::require($expected === []);
            $inventory = P::b64(hash('sha256', "AnyNote/p02-group-c2/hash/grant-inventory\0".pack('N3', 1, 0, $count).pack('N3', 0, $count, strlen(P::canonical($page))).P::binary(P::digest('p02-group-c2', 'grant-page', $page)), true));
            $epochs = [(object) ['key_epoch' => '0', 'epoch_digest' => $epoch, 'key_commitment' => $v->key_commitment]];
            $epochInventory = P::b64(hash('sha256', "AnyNote/p02-group-c2/hash/epochs\0".Json::canonicalize($epochs), true));
            Protocol::require($d->intent_digest === $epoch && $d->inventory_digest === $inventory && $d->record_count === (string) $count && $d->page_count === '1' && $d->epoch_inventory_digest === $epochInventory);
            Protocol::require(! DB::table('groups')->where('id', $b->group_id)->exists(), 'IDEMPOTENCY_MISMATCH');
            $g = $b->group_id;
            DB::table('groups')->insert(['id' => $g, 'owner_account_id' => $s->account_id, 'kind' => $kind, 'state' => 'active', 'policy_sequence' => 0, 'policy_digest' => $membership->digest, 'epoch_number' => 0, 'epoch_digest' => $epoch]);
            DB::table('group_memberships')->insert(['group_id' => $g, 'account_id' => $s->account_id, 'role' => 'owner', 'status' => 'active', 'joined_policy' => 0]);
            DB::table('group_policy_events')->insert(['id' => $p->operation_id, 'group_id' => $g, 'sequence' => 0, 'parent_digest' => null, 'digest' => $membership->digest, 'signed_record' => P::canonical($policy)]);
            DB::table('group_key_epochs')->insert(['id' => P::b64(random_bytes(16)), 'group_id' => $g, 'epoch_number' => 0, 'policy_digest' => $membership->digest, 'digest' => $epoch, 'signed_transition' => P::canonical($commit)]);
            foreach ($page->records as $record) {
                self::envelope($record);
            }
            $this->quota->apply($this->quota->lock($s->account_id, $g), $bytes, 0);
            $genesis = ['account_id' => $s->account_id, 'group_id' => $g, 'request_digest' => $hash, 'commit_record' => P::canonical($commit), 'grant_page' => P::canonical($page)];
            if (! $settings) {
                $genesis['device_id'] = $s->device_id;
                $genesis['operation_id'] = $b->operation_id;
            }
            DB::table($settings ? 'account_settings_genesis' : ($kind === 'shared' ? 'shared_group_geneses' : 'private_group_geneses'))->insert($genesis);
            $this->sync->append([['group_id' => $g, 'audience_account_id' => $s->account_id, 'kind' => $settings ? 'settings-genesis' : ($kind === 'shared' ? 'shared-group-genesis' : 'private-group-genesis'), 'object_id' => $g, 'revision_id' => null, 'digest' => P::digest('p02-group-c2', 'epoch-commit', $commit)]]);

            return ['version' => 1, 'group_id' => $g, 'commit' => $commit, 'pages' => [$page]];
        }, 3);
    }

    public function read(Request $r): array
    {
        return DB::transaction(function () use ($r) {
            $s = $this->sessions->current($r, true);
            $this->authorization->actor($this->sessions->secret($r));
            $row = DB::table('account_settings_genesis')->where('account_id', $s->account_id)->first();
            Protocol::require($row !== null, 'NOT_FOUND');
            $this->authorization->group($this->authorization->actor($this->sessions->secret($r)), $row->group_id);

            return ['version' => 1, 'group_id' => $row->group_id, 'commit' => json_decode($row->commit_record), 'pages' => [json_decode($row->grant_page)]];
        }, 3);
    }
}
