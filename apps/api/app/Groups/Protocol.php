<?php

namespace App\Groups;

use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Devices\Settings;
use Illuminate\Support\Facades\DB;
use stdClass;
use Truschery\Kanon\Json;

/** Exact frozen group-c2 authority predicates; transactions are owned by Service. */
final class Protocol
{
    public function __construct(private Authorization $authorization) {}

    public static function head(stdClass $g): stdClass
    {
        return (object) ['version' => (string) $g->policy_sequence, 'digest' => $g->policy_digest];
    }

    public static function epochHead(stdClass $g): stdClass
    {
        $row = DB::table('group_key_epochs')->where('group_id', $g->id)->where('epoch_number', $g->epoch_number)->first();
        D::require($row !== null, 'KEYS_PENDING');

        return (object) ['version' => (string) $g->epoch_number, 'digest' => P::digest('p02-group-c2', 'epoch-commit', json_decode($row->signed_transition))];
    }

    public static function policyRef(stdClass $g): stdClass
    {
        return (object) ['membership' => self::head($g), 'key_epoch' => (string) $g->epoch_number, 'epoch_digest' => $g->epoch_digest, 'history_checkpoint_digest' => $g->history_checkpoint_digest];
    }

    public static function members(stdClass $g): array
    {
        return DB::table('group_memberships as m')->join('account_identities as i', 'i.account_id', '=', 'm.account_id')->where('m.group_id', $g->id)->where('m.status', 'active')->orderBy('m.account_id')->get(['m.account_id', 'i.root_fingerprint', 'm.role'])->map(fn ($m) => (object) (array) $m)->all();
    }

    public function signer(stdClass $g, stdClass $sender, stdClass $record, string $cap = 'sign-content', ?array $roles = null): array
    {
        [$i,$d,$cert] = $this->authorization->certifiedDevice($sender->account_id, $sender->device_id);
        D::require(D::equal($sender, Settings::sender($i, $d)), 'ROSTER_CHANGED');
        D::require(in_array($cap, $cert->body->capabilities, true), 'ROLE_FORBIDDEN');
        if ($roles !== null) {
            $m = DB::table('group_memberships')->where('group_id', $g->id)->where('account_id', $sender->account_id)->where('status', 'active')->first();
            D::require($m && in_array($m->role, $roles, true), 'ROLE_FORBIDDEN');
        }
        D::require($record->body->service_id === config('api.service_id') && $record->body->group_id === $g->id, 'INVALID_SIGNATURE');
        P::verify('p02-group-c2', $record->body->purpose, $record->body, $record->signature, $cert->body->device_signing_key);

        return [$i, $d, $cert];
    }

    public function invitation(stdClass $g, stdClass $record): void
    {
        $b = $record->body;
        D::require($g->kind === 'shared' && $g->state === 'active', 'ROLE_FORBIDDEN');
        $this->signer($g, $b->signer, $record, 'sign-content', ['owner']);
        D::require(D::equal($b->policy, self::head($g)), 'POLICY_CHANGED');
        $i = DB::table('account_identities')->where('account_id', $b->target_account_id)->first();
        $u = DB::table('users')->where('id', $b->target_account_id)->first();
        D::require($i && $u && $u->status === 'active' && $i->root_fingerprint === $b->target_root_fingerprint, 'NOT_FOUND');
        D::require(! DB::table('group_memberships')->where('group_id', $g->id)->where('account_id', $b->target_account_id)->where('status', 'active')->exists(), 'ROLE_FORBIDDEN');
        $ms = (int) floor(microtime(true) * 1000);
        D::require((int) $b->expires_at > $ms && (int) $b->expires_at <= $ms + 172800000, 'ENROLLMENT_EXPIRED');
    }

    public function acceptance(stdClass $g, stdClass $invite, stdClass $record): void
    {
        $b = $record->body;
        $i = $invite->body;
        D::require($b->operation_id === $i->operation_id && $b->invitation_digest === P::digest('p02-group-c2', 'invitation', $invite) && D::equal($b->policy, self::head($g)) && $b->signer->account_id === $i->target_account_id && $b->signer->root_fingerprint === $i->target_root_fingerprint, 'INVALID_SIGNATURE');
        $this->signer($g, $b->signer, $record);
    }

    public function policy(stdClass $g, stdClass $record, bool $admission = false): array
    {
        $b = $record->body;
        $old = self::members($g);
        $next = json_decode(Json::canonicalize($old));
        $this->signer($g, $b->signer, $record, 'sign-content', ['owner']);
        D::require($b->action !== 'genesis' && D::equal($b->predecessor, self::head($g)) && $b->version === (string) ($g->policy_sequence + 1), 'POLICY_CHANGED');
        $loss = false;
        $target = $b->payload->target_account_id ?? null;
        $found = null;
        foreach ($next as $m) {
            if ($m->account_id === $target) {
                $found = $m;
            }
        }
        switch ($b->action) {
            case 'admit':
                D::require($admission && count($next) < 20, 'ROLE_FORBIDDEN');
                $inv = $b->payload->invitation;
                $acc = $b->payload->acceptance;
                $this->invitation($g, $inv);
                $this->acceptance($g, $inv, $acc);
                D::require($b->operation_id === $inv->body->operation_id, 'INVALID_SIGNATURE');
                $next[] = (object) ['account_id' => $inv->body->target_account_id, 'root_fingerprint' => $inv->body->target_root_fingerprint, 'role' => $inv->body->role];
                break;
            case 'remove':
                D::require($found && $found->role !== 'owner', 'ROLE_FORBIDDEN');
                $next = array_values(array_filter($next, fn ($m) => $m->account_id !== $target));
                $loss = true;
                break;
            case 'role':
                D::require($found && $found->role !== 'owner' && $found->role !== $b->payload->role, 'ROLE_FORBIDDEN');
                $loss = $found->role === 'editor' && $b->payload->role === 'reader';
                $found->role = $b->payload->role;
                break;
            case 'archive': D::require($g->state === 'active', 'ROLE_FORBIDDEN');
                break;
            case 'unarchive': D::require($g->state === 'archived', 'ROLE_FORBIDDEN');
                break;
            case 'transfer':
                D::require($g->kind === 'shared' && $record->cosignature !== null, 'ROLE_FORBIDDEN');
                $incoming = $b->payload->incoming_signer;
                $member = null;
                foreach ($next as $m) {
                    if ($m->account_id === $incoming->account_id && $m->root_fingerprint === $incoming->root_fingerprint) {
                        $member = $m;
                    }
                }
                D::require($member && $member->role !== 'owner', 'ROLE_FORBIDDEN');
                [$i,$device,$cert] = $this->authorization->certifiedDevice($incoming->account_id, $incoming->device_id);
                D::require(D::equal($incoming, Settings::sender($i, $device)) && in_array('sign-content', $cert->body->capabilities, true), 'ROSTER_CHANGED');
                P::verify('p02-group-c2', $b->purpose, $b, $record->cosignature, $cert->body->device_signing_key);
                foreach ($next as $m) {
                    if ($m->role === 'owner') {
                        $m->role = 'editor';
                    }
                }
                $member->role = 'owner';
                break;
            default: D::require(false, 'INVALID_REQUEST');
        }
        if ($b->action !== 'transfer') {
            D::require($record->cosignature === null, 'INVALID_SIGNATURE');
        }
        usort($next, fn ($a, $b) => strcmp($a->account_id, $b->account_id));
        D::require(D::equal($next, $b->members) && count(array_filter($next, fn ($m) => $m->role === 'owner')) === 1, 'INVALID_SIGNATURE');

        return [$next, $loss];
    }

    public static function epochs(stdClass $g): array
    {
        return DB::table('group_key_epochs')->where('group_id', $g->id)->orderBy('epoch_number')->get()->map(function ($r) {
            $i = json_decode($r->signed_transition)->body->intent->body;

            return (object) ['key_epoch' => $i->next_epoch, 'epoch_digest' => $r->digest, 'key_commitment' => $i->key_commitment];
        })->all();
    }

    public static function rosters(array $members): array
    {
        $rows = [];
        foreach ($members as $m) {
            $i = DB::table('account_identities')->where('account_id', $m->account_id)->first();
            $u = DB::table('users')->where('id', $m->account_id)->first();
            D::require($i && $u && $u->status === 'active' && $i->root_fingerprint === $m->root_fingerprint, 'ROSTER_CHANGED');
            $rows[] = (object) ['account_id' => $m->account_id, 'root_fingerprint' => $m->root_fingerprint, 'recovery_generation' => (string) $i->recovery_generation, 'roster' => D::head($i)];
        }

        return $rows;
    }

    public function intent(stdClass $g, stdClass $record, ?stdClass $policy): array
    {
        $b = $record->body;
        $members = self::members($g);
        $head = self::head($g);
        if ($policy) {
            [$members] = $this->policy($g, $policy, true);
            D::require($policy->body->action === 'admit' && $policy->body->operation_id === $b->operation_id && $b->reason === 'admission', 'INVALID_SIGNATURE');
            $head = (object) ['version' => $policy->body->version, 'digest' => P::digest('p02-group-c2', 'policy', $policy)];
        }
        $roles = ['owner', 'editor'];
        if ($b->reason === 'roster-maintenance') {
            $roles[] = 'reader';
        }
        [$i,$device,$cert] = $this->signer($g, $b->signer, $record, 'distribute-group-key', $roles);
        D::require(D::equal($b->expected_policy, self::head($g)) && D::equal($b->membership, $head) && D::equal($b->previous_epoch, self::epochHead($g)), 'POLICY_CHANGED');
        D::require($b->next_epoch === (string) ($g->epoch_number + 1) && D::equal($b->retained_epochs, self::epochs($g)) && $b->history_checkpoint_digest === $g->history_checkpoint_digest, 'REKEY_REQUIRED');
        D::require(D::equal($b->rosters, self::rosters($members)), 'ROSTER_CHANGED');
        $ms = (int) floor(microtime(true) * 1000);
        D::require((int) $b->expires_at > $ms && (int) $b->expires_at <= $ms + 600000, 'ENROLLMENT_EXPIRED');
        foreach (self::epochs($g) as $e) {
            D::require($e->key_commitment !== $b->key_commitment, 'INVALID_SIGNATURE');
        }
        // A commitment exposed by cancelled/expired staging may never become a future epoch.
        foreach (DB::table('security_transition_staging')->where('group_id', $g->id)->whereIn('state', ['cancelled', 'expired'])->get() as $old) {
            $st = json_decode($old->signed_descriptor);
            if (isset($st->intent)) {
                D::require($st->intent->body->key_commitment !== $b->key_commitment, 'INVALID_SIGNATURE');
            }
        }
        $prior = DB::table('group_key_epochs')->where('group_id', $g->id)->where('epoch_number', $g->epoch_number)->first();
        $changed = ! D::equal(json_decode($prior->signed_transition)->body->intent->body->rosters, self::rosters(self::members($g)));
        switch ($b->reason) {
            case 'admission': D::require($policy && ! $g->rekey_required && ! $g->history_closure_required && $g->history_checkpoint_digest !== null && $g->state === 'active', 'HISTORY_CLOSURE_REQUIRED');
                break;
            case 'member-removal': D::require(! $policy && $g->rekey_required && $this->lastRemoval($g), 'ROLE_FORBIDDEN');
                break;
            case 'roster-maintenance': D::require(! $policy && $changed && ! $this->lastRemoval($g), 'ROLE_FORBIDDEN');
                break;
            case 'optional': D::require(! $policy && ! $g->rekey_required && ! $changed, 'ROLE_FORBIDDEN');
                break;
            default: D::require(false, 'INVALID_REQUEST');
        }

        return [$members, $head, $cert];
    }

    private function lastRemoval(stdClass $g): bool
    {
        // Only a removal after the last epoch needs writer-led member maintenance.
        $old = DB::table('group_key_epochs')->where('group_id', $g->id)->where('epoch_number', $g->epoch_number)->first();
        $version = json_decode($old->signed_transition)->body->intent->body->membership->version;

        return DB::table('group_policy_events')->where('group_id', $g->id)->where('sequence', '>', $version)->get()->contains(fn ($r) => json_decode($r->signed_record)->body->action === 'remove');
    }

    public function commit(stdClass $g, stdClass $commit, array $pages): array
    {
        $b = $commit->body;
        [$members,$membership,$cert] = $this->intent($g, $b->intent, $b->policy);
        $key = $cert->body->device_signing_key;
        foreach ([$commit, $b->descriptor] as $r) {
            D::require($r->body->service_id === config('api.service_id') && $r->body->group_id === $g->id && $r->body->operation_id === $b->intent->body->operation_id, 'INVALID_SIGNATURE');
            P::verify('p02-group-c2', $r->body->purpose, $r->body, $r->signature, $key);
        }
        $d = $b->descriptor->body;
        $epoch = P::digest('p02-group-c2', 'epoch-intent', $b->intent);
        $epochs = [...self::epochs($g), (object) ['key_epoch' => $b->intent->body->next_epoch, 'epoch_digest' => $epoch, 'key_commitment' => $b->intent->body->key_commitment]];
        $recipients = [];
        foreach ($members as $m) {
            $i = DB::table('account_identities')->where('account_id', $m->account_id)->first();
            foreach (DB::table('devices')->where('account_id', $m->account_id)->where('status', 'active')->orderBy('id')->get() as $device) {
                [,,$c] = $this->authorization->certifiedDevice($m->account_id, $device->id);
                D::require(in_array('receive-group-key', $c->body->capabilities, true), 'ROLE_FORBIDDEN');
                $recipients[] = Settings::recipient($i, $device);
            }
            $recipients[] = Settings::recipient($i, null);
        }
        $expected = [];
        foreach ($epochs as $e) {
            foreach ($recipients as $r) {
                $ctx = (object) ['purpose' => 'group-key-distribution', 'contract' => 'p02-identity-c1', 'protocol' => 'anynote', 'protocol_version' => 1, 'service_id' => config('api.service_id'), 'group_id' => $g->id, 'key_epoch' => $e->key_epoch, 'epoch_digest' => $e->epoch_digest, 'membership_head' => $membership, 'operation_id' => $b->operation_id, 'issuer' => $b->intent->body->signer, 'recipient' => $r];
                $expected[P::canonical($ctx)] = $ctx;
            }
        }
        $count = array_sum(array_map(fn ($p) => count($p->records), $pages));
        D::require(count($pages) > 0 && count($pages) <= 1000 && $count === count($expected), 'KEYS_PENDING');
        $hash = hash_init('sha256');
        hash_update($hash, "AnyNote/p02-group-c2/hash/grant-inventory\0".pack('N3', count($pages), 0, $count));
        $last = null;
        $records = [];
        $bytes = 0;
        foreach ($pages as $n => $p) {
            D::require($p->service_id === config('api.service_id') && $p->group_id === $g->id && $p->operation_id === $b->operation_id && $p->page_index === (string) $n, 'INVALID_SIGNATURE');
            if ($n < count($pages) - 1 && count($p->records) < 500) {
                $aug = clone $p;
                $aug->records = [...$p->records, $pages[$n + 1]->records[0]];
                D::require(strlen(P::canonical($aug)) > 1048576, 'INVALID_REQUEST');
            }
            hash_update($hash, pack('N3', $n, count($p->records), strlen(P::canonical($p))).P::binary(P::digest('p02-group-c2', 'grant-page', $p)));
            foreach ($p->records as $r) {
                $ctx = $r->body->context;
                $order = str_pad($ctx->key_epoch, 19, '0', STR_PAD_LEFT).'/'.$ctx->recipient->account_id.'/'.$ctx->recipient->kind.'/'.($ctx->recipient->device_id ?? '');
                D::require($last === null || strcmp($last, $order) < 0, 'INVALID_SIGNATURE');
                $last = $order;
                $c = P::canonical($ctx);
                D::require(isset($expected[$c]), 'INVALID_SIGNATURE');
                unset($expected[$c]);
                P::verify('p02-identity-c1', 'group-key-distribution', $r->body, $r->signature, $key);
                $records[] = $r;
                $bytes += strlen(P::binary($r->body->sealed_ciphertext));
            }
        }
        D::require($expected === [] && $d->intent_digest === $epoch && D::equal($d->membership, $membership) && D::equal($d->signer, $b->intent->body->signer) && $d->inventory_digest === P::b64(hash_final($hash, true)) && $d->record_count === (string) $count && $d->page_count === (string) count($pages) && $d->epoch_inventory_digest === P::b64(hash('sha256', "AnyNote/p02-group-c2/hash/epochs\0".Json::canonicalize($epochs), true)), 'INVALID_SIGNATURE');

        return [$members, $membership, $records, $bytes];
    }
}
