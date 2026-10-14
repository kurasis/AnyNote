<?php

namespace App\Groups;

use App\Auth\Sessions;
use App\Backend\Actor;
use App\Backend\Authorization;
use App\Backend\QuotaLedger;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Devices\Settings;
use App\Notes\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Durable invitation, staging, CAS and current multi-account authority. No private keys. */
final class Service
{
    public function __construct(private Sessions $sessions, private Authorization $auth, private Protocol $protocol, private QuotaLedger $quota, private SyncWriter $sync) {}

    private function locks(Request $r, string $group, array $extra = []): Actor
    {
        // Read discovery is not authority. Compare/reload after sorted account locks.
        $session = $this->sessions->current($r);
        $ids = DB::table('group_memberships')->where('group_id', $group)->where('status', 'active')->pluck('account_id')->all();
        $ids = array_unique([...$ids, ...$extra, $session->account_id]);
        sort($ids, SORT_STRING);
        D::require(count($ids) <= 22, 'RESOURCE_LIMIT');
        foreach ($ids as $id) {
            DB::table('users')->where('id', $id)->lockForUpdate()->first();
            DB::table('account_identities')->where('account_id', $id)->lockForUpdate()->first();
        }
        $r->attributes->set('p10_locked_accounts', $ids);
        $this->sessions->current($r, true);

        return $this->auth->actor($this->sessions->secret($r));
    }

    private function pending(stdClass $g, bool $live = true): ?stdClass
    {
        $p = DB::table('security_transition_staging')->where('pending_group_id', $g->id)->lockForUpdate()->first();
        if ($p && $live && $p->expires_at <= now()->format('Y-m-d H:i:s')) {
            DB::table('security_transition_staging')->where('id', $p->id)->update(['pending_group_id' => null, 'state' => 'expired']);
            DB::table('membership_invites')->where('id', $p->id)->whereIn('state', ['pending', 'accepted'])->update(['state' => 'expired']);

            return null;
        }

        return $p;
    }

    private function cancelPending(stdClass $g): void
    {
        $p = $this->pending($g);
        if (! $p) {
            return;
        }
        DB::table('security_transition_staging')->where('id', $p->id)->update(['pending_group_id' => null, 'state' => 'cancelled']);
        DB::table('membership_invites')->where('id', $p->id)->whereIn('state', ['pending', 'accepted'])->update(['state' => 'declined']);
    }

    private function result(stdClass $g, string $op, string $state, string $digest): array
    {
        return ['version' => 1, 'group_id' => $g->id, 'operation_id' => $op, 'state' => $state, 'digest' => $digest];
    }

    private function journal(stdClass $g, stdClass $event): void
    {
        $q = DB::table('group_transition_journal')->where('group_id', $g->id);
        $count = $q->count();
        $bytes = (int) $q->sum(DB::raw('OCTET_LENGTH(record)'));
        D::require($count < 1000 && $bytes + strlen(P::canonical($event)) <= 3145728, 'RESOURCE_LIMIT');
        DB::table('group_transition_journal')->insert(['group_id' => $g->id, 'position' => $count, 'record' => P::canonical($event)]);
    }

    private function applyPolicy(stdClass $g, stdClass $p, array $members, bool $loss): void
    {
        $b = $p->body;
        $digest = P::digest('p02-group-c2', 'policy', $p);
        DB::table('group_policy_events')->insert(['id' => $b->operation_id, 'group_id' => $g->id, 'sequence' => $b->version, 'parent_digest' => $g->policy_digest, 'digest' => $digest, 'signed_record' => P::canonical($p)]);
        $new = array_column(array_map(fn ($m) => (array) $m, $members), 'account_id');
        DB::table('group_memberships')->where('group_id', $g->id)->where('status', 'active')->whereNotIn('account_id', $new)->update(['status' => 'removed', 'removed_policy' => $b->version]);
        foreach ($members as $m) {
            $old = DB::table('group_memberships')->where('group_id', $g->id)->where('account_id', $m->account_id)->first();
            if ($old) {
                DB::table('group_memberships')->where('group_id', $g->id)->where('account_id', $m->account_id)->update(['role' => $m->role, 'status' => 'active', 'removed_policy' => null]);
            } else {
                DB::table('group_memberships')->insert(['group_id' => $g->id, 'account_id' => $m->account_id, 'role' => $m->role, 'status' => 'active', 'joined_policy' => $b->version]);
            }
        }
        $fields = ['policy_sequence' => $b->version, 'policy_digest' => $digest, 'owner_account_id' => array_values(array_filter($members, fn ($m) => $m->role === 'owner'))[0]->account_id];
        if ($loss) {
            $fields['history_closure_required'] = true;
        }
        if ($b->action === 'remove') {
            $fields['rekey_required'] = true;
        }
        if (in_array($b->action, ['archive', 'unarchive'], true)) {
            $fields['state'] = $b->action === 'archive' ? 'archived' : 'active';
        }
        DB::table('groups')->where('id', $g->id)->update($fields);
    }

    private function receipt(Actor $a, stdClass $g, string $family, string $op, stdClass $body, ?array $result = null): ?array
    {
        $q = DB::table('group_security_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $op)->where('family', $family);
        D::require(! DB::table('mutation_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $op)->exists(), 'IDEMPOTENCY_MISMATCH');
        D::require(! DB::table('file_publication_ids')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $op)->exists(), 'IDEMPOTENCY_MISMATCH');
        foreach (['private_group_geneses', 'shared_group_geneses'] as $table) {
            D::require(! DB::table($table)->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $op)->exists(), 'IDEMPOTENCY_MISMATCH');
        }
        $digest = P::b64(hash('sha256', P::canonical($body), true));
        $old = $q->first();
        if ($old) {
            D::require($old->group_id === $g->id && $old->request_digest === $digest, 'IDEMPOTENCY_MISMATCH');

            return (array) json_decode($old->result);
        }
        if ($result) {
            DB::table('group_security_receipts')->insert(['account_id' => $a->accountId, 'device_id' => $a->deviceId, 'operation_id' => $op, 'family' => $family, 'group_id' => $g->id, 'request_digest' => $digest, 'result' => json_encode($result, JSON_THROW_ON_ERROR)]);
        }

        return null;
    }

    public function mutate(Request $r, string $group, string $family, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $group, $family, $body) {
            $record = $body->invitation ?? $body->acceptance ?? $body->policy ?? $body->intent ?? $body->commit ?? $body->history ?? null;
            $extras = [];
            if (isset($body->invitation)) {
                $extras[] = $body->invitation->body->target_account_id;
            }
            if (isset($body->policy) && $body->policy) {
                foreach ($body->policy->body->members as $m) {
                    $extras[] = $m->account_id;
                }
            }
            if (isset($body->commit->body->policy) && $body->commit->body->policy) {
                foreach ($body->commit->body->policy->body->members as $m) {
                    $extras[] = $m->account_id;
                }
            }
            $a = $this->locks($r, $group, $extras);
            $g = DB::table('groups')->where('id', $group)->lockForUpdate()->first();
            D::require($g && $g->state !== 'purged', 'NOT_FOUND');
            $currentAccounts = DB::table('group_memberships')->where('group_id', $g->id)->where('status', 'active')->pluck('account_id')->all();
            D::require(array_diff($currentAccounts, $r->attributes->get('p10_locked_accounts')) === [], 'ROSTER_CHANGED');
            $op = $record?->body->operation_id ?? $body->operation_id ?? $body->page->operation_id;
            $pending = $this->pending($g);
            $targetCancel = false;
            if ($family === 'cancel') {
                $candidate = DB::table('membership_invites')->where('id', $op)->where('group_id', $g->id)->first();
                $targetCancel = $candidate && json_decode($candidate->signed_intent)->body->target_account_id === $a->accountId && $candidate->target_root === $a->rootFingerprint;
            }
            if ($family === 'accept') {
                $invite = DB::table('membership_invites')->where('id', $op)->where('group_id', $g->id)->first();
                D::require($invite && json_decode($invite->signed_intent)->body->target_account_id === $a->accountId, 'NOT_FOUND');
            } elseif (! $targetCancel) {
                $this->auth->group($a, $g->id);
            }
            $receiptFamily = $family === 'page' ? 'page'.$body->page->page_index : $family;
            if ($old = $this->receipt($a, $g, $receiptFamily, $op, $body)) {
                return $old;
            }
            $state = '';
            $digest = P::b64(hash('sha256', P::canonical($body), true));
            $sync = false;
            switch ($family) {
                case 'invite':
                    D::require($record->body->signer->account_id === $a->accountId && $record->body->signer->device_id === $a->deviceId && ! $pending, 'ROLE_FORBIDDEN');
                    $this->protocol->invitation($g, $record);
                    D::require(! DB::table('membership_invites')->where('id', $op)->exists(), 'IDEMPOTENCY_MISMATCH');
                    DB::table('membership_invites')->insert(['id' => $op, 'group_id' => $g->id, 'target_root' => $record->body->target_root_fingerprint, 'role' => $record->body->role, 'signed_intent' => P::canonical($record), 'state' => 'pending', 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil((int) $record->body->expires_at / 1000))]);
                    DB::table('security_transition_staging')->insert(['id' => $op, 'group_id' => $g->id, 'pending_group_id' => $g->id, 'expected_policy_digest' => $g->policy_digest, 'expected_rosters' => '[]', 'signed_descriptor' => P::canonical((object) ['invitation' => $record, 'acceptance' => null, 'intent' => null, 'policy' => null]), 'state' => 'staged', 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil((int) $record->body->expires_at / 1000))]);
                    $state = 'INVITED';
                    break;
                case 'accept':
                    D::require($pending && $pending->id === $op, 'ENROLLMENT_EXPIRED');
                    $i = json_decode($invite->signed_intent);
                    $this->protocol->invitation($g, $i);
                    $this->protocol->acceptance($g, $i, $record);
                    D::require($record->body->signer->device_id === $a->deviceId && $invite->state === 'pending', 'ROLE_FORBIDDEN');
                    DB::table('membership_invites')->where('id', $op)->update(['signed_acceptance' => P::canonical($record), 'state' => 'accepted']);
                    $st = json_decode($pending->signed_descriptor);
                    $st->acceptance = $record;
                    DB::table('security_transition_staging')->where('id', $op)->update(['signed_descriptor' => P::canonical($st)]);
                    $state = 'ACCEPTED_PENDING_GRANTS';
                    break;
                case 'policy':
                    D::require($record->body->signer->account_id === $a->accountId && $record->body->signer->device_id === $a->deviceId, 'ROLE_FORBIDDEN');
                    [$members,$loss] = $this->protocol->policy($g, $record);
                    if ($record->body->action === 'transfer') {
                        $this->checkConsent($g, $record, $a);
                    }
                    $this->cancelPending($g);
                    $this->applyPolicy($g, $record, $members, $loss);
                    $this->journal($g, (object) ['kind' => 'policy', 'policy' => $record]);
                    $state = 'POLICY_COMMITTED';
                    $sync = true;
                    break;
                case 'consent':
                    D::require($record->body->action === 'transfer' && $record->body->payload->incoming_signer->account_id === $a->accountId && $record->body->payload->incoming_signer->device_id === $a->deviceId && $a->recent, 'ROLE_FORBIDDEN');
                    $this->protocol->policy($g, $record);
                    DB::table('group_owner_consents')->insert(['group_id' => $g->id, 'policy_digest' => P::digest('p02-group-c2', 'policy', $record), 'account_id' => $a->accountId, 'device_id' => $a->deviceId, 'session_id' => $a->sessionId, 'expires_at' => now()->addMinutes(5)]);
                    $state = 'OWNER_CONSENT';
                    break;
                case 'begin':
                    D::require($body->intent->body->signer->account_id === $a->accountId && $body->intent->body->signer->device_id === $a->deviceId, 'ROLE_FORBIDDEN');
                    $this->protocol->intent($g, $body->intent, $body->policy);
                    $st = (object) ['invitation' => null, 'acceptance' => null, 'intent' => $body->intent, 'policy' => $body->policy];
                    if ($body->policy) {
                        D::require($pending && $pending->id === $op, 'KEYS_PENDING');
                        $prior = json_decode($pending->signed_descriptor);
                        D::require($prior->intent === null && D::equal($prior->invitation, $body->policy->body->payload->invitation) && D::equal($prior->acceptance, $body->policy->body->payload->acceptance), 'KEYS_PENDING');
                        $st->invitation = $prior->invitation;
                        $st->acceptance = $prior->acceptance;
                        DB::table('security_transition_staging')->where('id', $op)->update(['signed_descriptor' => P::canonical($st), 'expected_rosters' => json_encode($body->intent->body->rosters, JSON_THROW_ON_ERROR), 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil((int) $body->intent->body->expires_at / 1000))]);
                    } else {
                        D::require(! $pending, 'ROLE_FORBIDDEN');
                        DB::table('security_transition_staging')->insert(['id' => $op, 'group_id' => $g->id, 'pending_group_id' => $g->id, 'expected_policy_digest' => $g->policy_digest, 'expected_rosters' => json_encode($body->intent->body->rosters, JSON_THROW_ON_ERROR), 'signed_descriptor' => P::canonical($st), 'state' => 'staged', 'expires_at' => gmdate('Y-m-d H:i:s', (int) ceil((int) $body->intent->body->expires_at / 1000))]);
                    }$state = 'STAGING';
                    break;
                case 'page':
                    D::require($pending && $pending->id === $op, 'KEYS_PENDING');
                    $st = json_decode($pending->signed_descriptor);
                    D::require($st->intent && $st->intent->body->signer->account_id === $a->accountId && $st->intent->body->signer->device_id === $a->deviceId, 'ROLE_FORBIDDEN');
                    $this->protocol->intent($g, $st->intent, $st->policy);
                    $page = $body->page;
                    D::require($page->group_id === $g->id && $page->service_id === config('api.service_id') && (int) $page->page_index < 1000, 'INVALID_REQUEST');
                    $q = DB::table('security_transition_pages')->where('transition_id', $op);
                    D::require((int) $q->sum(DB::raw('OCTET_LENGTH(page_record)')) + strlen(P::canonical($page)) <= 16777216 && $q->count() < 1000, 'RESOURCE_LIMIT');
                    DB::table('security_transition_pages')->insert(['id' => P::b64(random_bytes(16)), 'transition_id' => $op, 'page_index' => $page->page_index, 'digest' => P::digest('p02-group-c2', 'grant-page', $page), 'page_record' => P::canonical($page)]);
                    $state = 'STAGED';
                    break;
                case 'commit':
                    D::require($pending && $pending->id === $op, 'KEYS_PENDING');
                    $st = json_decode($pending->signed_descriptor);
                    D::require($st->intent && D::equal($st->intent, $body->commit->body->intent) && D::equal($st->policy, $body->commit->body->policy) && $st->intent->body->signer->account_id === $a->accountId && $st->intent->body->signer->device_id === $a->deviceId, 'INVALID_SIGNATURE');
                    $pages = DB::table('security_transition_pages')->where('transition_id', $op)->orderBy('page_index')->get()->map(fn ($p) => json_decode($p->page_record))->all();
                    [$members,$head,$records,$bytes] = $this->protocol->commit($g, $body->commit, $pages);
                    $this->journal($g, (object) ['kind' => 'epoch', 'commit' => $body->commit, 'pages' => $pages]);
                    if ($st->policy) {
                        $this->applyPolicy($g, $st->policy, $members, false);
                    }
                    $intent = $st->intent;
                    $epoch = P::digest('p02-group-c2', 'epoch-intent', $intent);
                    DB::table('group_key_epochs')->insert(['id' => P::b64(random_bytes(16)), 'group_id' => $g->id, 'epoch_number' => $intent->body->next_epoch, 'policy_digest' => $head->digest, 'digest' => $epoch, 'signed_transition' => P::canonical($body->commit)]);
                    foreach ($records as $rec) {
                        Settings::envelope($rec);
                    }
                    if (in_array($intent->body->reason, ['member-removal', 'roster-maintenance'], true)) {
                        $reserve = DB::table('quota_ledgers')->where('scope', 'security')->lockForUpdate()->first();
                        D::require($reserve && $bytes <= (int) $reserve->limit_bytes - (int) $reserve->committed_bytes - (int) $reserve->reserved_bytes, 'INSUFFICIENT_STORAGE');
                        DB::table('quota_ledgers')->where('scope', 'security')->increment('committed_bytes', $bytes);
                        DB::table('quota_movements')->insert(['id' => P::b64(random_bytes(16)), 'scope' => 'security', 'committed_delta' => $bytes, 'reserved_delta' => 0]);
                    } else {
                        $this->quota->apply($this->quota->lock($a->accountId, $g->id), $bytes, 0);
                    }
                    DB::table('groups')->where('id', $g->id)->update(['epoch_number' => $intent->body->next_epoch, 'epoch_digest' => $epoch, 'rekey_required' => false]);
                    DB::table('security_transition_staging')->where('id', $op)->update(['pending_group_id' => null, 'state' => 'committed']);
                    DB::table('membership_invites')->where('id', $op)->where('state', 'accepted')->update(['state' => 'activated']);
                    $state = 'ACTIVATED';
                    $sync = true;
                    break;
                case 'history':
                    D::require($record->body->signer->account_id === $a->accountId && $record->body->signer->device_id === $a->deviceId, 'ROLE_FORBIDDEN');
                    $this->history($g, $record, $body->pages);
                    $this->cancelPending($g);
                    $this->journal($g, (object) ['kind' => 'history', 'history' => $record, 'pages' => $body->pages]);
                    DB::table('groups')->where('id', $g->id)->update(['history_checkpoint_digest' => P::digest('p02-file-c1', 'history-checkpoint', $record->body->descriptor), 'history_closure_required' => false]);
                    $state = 'HISTORY_CLOSED';
                    $sync = true;
                    break;
                case 'cancel':
                    D::require($pending && $pending->id === $op, 'NOT_FOUND');
                    $st = json_decode($pending->signed_descriptor);
                    D::require($targetCancel || $g->owner_account_id === $a->accountId || ($st->intent?->body->signer->account_id === $a->accountId && $st->intent?->body->signer->device_id === $a->deviceId), 'ROLE_FORBIDDEN');
                    $this->cancelPending($g);
                    $state = 'CANCELLED';
                    break;
                default: D::require(false, 'NOT_FOUND');
            }
            $result = $this->result($g, $op, $state, $digest);
            $this->receipt($a, $g, $receiptFamily, $op, $body, $result);
            if ($sync) {
                $this->sync->append([['group_id' => $g->id, 'audience_account_id' => null, 'kind' => 'group-'.$family, 'object_id' => $g->id, 'revision_id' => null, 'digest' => $digest]]);
            }

            return $result;
        }, 3);
    }

    private function checkConsent(stdClass $g, stdClass $policy, Actor $a): void
    {
        D::require($a->recent, 'ROLE_FORBIDDEN');
        $i = $policy->body->payload->incoming_signer;
        $c = DB::table('group_owner_consents')->where('group_id', $g->id)->where('policy_digest', P::digest('p02-group-c2', 'policy', $policy))->where('account_id', $i->account_id)->where('device_id', $i->device_id)->where('expires_at', '>', now())->first();
        D::require($c !== null, 'ROLE_FORBIDDEN');
        $s = DB::table('auth_sessions')->where('id', $c->session_id)->first();
        D::require($s && $s->state === 'trusted' && $s->device_id === $i->device_id && $s->expires_at > now()->format('Y-m-d H:i:s') && $s->authenticated_at >= now()->subMinutes(5)->format('Y-m-d H:i:s'), 'ROLE_FORBIDDEN');
    }

    private function history(stdClass $g, stdClass $record, array $pages): void
    {
        $b = $record->body;
        $d = $b->descriptor;
        [,,$cert] = $this->protocol->signer($g, $b->signer, $record, 'sign-content', ['owner', 'editor']);
        $hist = DB::table('group_transition_journal')->where('group_id', $g->id)->orderByDesc('position')->get()->map(fn ($r) => json_decode($r->record))->first(fn ($r) => $r->kind === 'history');
        $head = $hist ? (object) ['version' => $hist->history->body->sequence, 'digest' => P::digest('p02-group-c2', 'history', $hist->history)] : null;
        D::require(D::equal($b->predecessor, $head) && $b->sequence === ($head ? (string) ((int) $head->version + 1) : '0') && D::equal($d->closed_policy, Protocol::policyRef($g)) && D::equal($d->closed_rosters, Protocol::rosters(Protocol::members($g))) && $d->predecessor_checkpoint_digest === $g->history_checkpoint_digest, 'HISTORY_CLOSURE_REQUIRED');
        $sender = $b->signer;
        $author = (object) ['account_id' => $sender->account_id, 'device_id' => $sender->device_id, 'root_fingerprint' => $sender->root_fingerprint, 'recovery_generation' => $sender->recovery_generation, 'roster' => $sender->roster_head];
        D::require(D::equal($d->signer, $author), 'INVALID_SIGNATURE');
        P::verify('p02-file-c1', 'history-checkpoint', $d, $b->descriptor_signature, $cert->body->device_signing_key);
        $rows = DB::table('object_revisions')->where('group_id', $g->id)->orderBy('revision_id')->get();
        D::require($rows->count() <= 5000, 'RESOURCE_LIMIT');
        $expected = [];
        foreach ($rows as $r) {
            $c = json_decode($r->signed_envelope)->header->context;
            $expected[$r->revision_id] = (object) ['object_kind' => $c->object_kind, 'object_id' => $r->object_id, 'revision_id' => $r->revision_id, 'envelope_digest' => $r->envelope_digest, 'parents' => $c->parents, 'payload_status' => 'retained'];
        }
        foreach (DB::table('file_versions')->where('group_id', $g->id)->whereNotNull('manifest_record')->get() as $file) {
            $c = json_decode($file->manifest_record)->envelope->header->context;
            $expected[$file->id] = (object) ['object_kind' => 'file-manifest', 'object_id' => $file->file_id, 'revision_id' => $file->id, 'envelope_digest' => $file->manifest_digest, 'parents' => $c->parents, 'payload_status' => $file->state === 'deleted' ? 'pruned' : 'retained'];
        }
        D::require(count($expected) <= 5000, 'RESOURCE_LIMIT');
        $count = array_sum(array_map(fn ($p) => count($p->records), $pages));
        D::require($count === count($expected) && $d->record_count === (string) $count && $d->page_count === (string) count($pages), 'HISTORY_CLOSURE_REQUIRED');
        $h = hash_init('sha256');
        hash_update($h, "AnyNote/p02-file-c1/hash/history-inventory\0".pack('N3', count($pages), 0, $count));
        $last = null;
        foreach ($pages as $n => $p) {
            D::require($p->service_id === config('api.service_id') && $p->group_id === $g->id && $p->page_index === (string) $n, 'INVALID_SIGNATURE');
            if ($n < count($pages) - 1 && count($p->records) < 500) {
                $aug = clone $p;
                $aug->records = [...$p->records, $pages[$n + 1]->records[0]];
                D::require(strlen(P::canonical($aug)) > 1048576, 'INVALID_REQUEST');
            }
            hash_update($h, pack('N3', $n, count($p->records), strlen(P::canonical($p))).P::binary(P::digest('p02-file-c1', 'history-page', $p)));
            foreach ($p->records as $rec) {
                D::require(($last === null || strcmp($last, $rec->revision_id) < 0) && isset($expected[$rec->revision_id]) && D::equal($rec, $expected[$rec->revision_id]), 'HISTORY_CLOSURE_REQUIRED');
                $last = $rec->revision_id;
                unset($expected[$rec->revision_id]);
            }
        }
        D::require($expected === [] && $d->inventory_digest === P::b64(hash_final($h, true)), 'HISTORY_CLOSURE_REQUIRED');
    }

    public function read(Request $r, string $group): array
    {
        return DB::transaction(function () use ($r, $group) {
            $a = $this->locks($r, $group);
            $g = $this->auth->group($a, $group);
            $s = app(Repository::class)->status($a, $g);
            $events = DB::table('group_transition_journal')->where('group_id', $group)->orderBy('position')->get()->map(fn ($p) => json_decode($p->record))->all();
            $pending = $this->pending($g);
            $p = null;
            if ($pending) {
                $st = json_decode($pending->signed_descriptor);
                $p = ['operation_id' => $pending->id, 'state' => $st->intent ? 'STAGING' : ($st->acceptance ? 'ACCEPTED_PENDING_GRANTS' : 'INVITED'), 'invitation' => $st->invitation, 'acceptance' => $st->acceptance, 'intent' => $st->intent, 'policy' => $st->policy, 'pages' => DB::table('security_transition_pages')->where('transition_id', $pending->id)->orderBy('page_index')->get()->map(fn ($r) => json_decode($r->page_record))->all()];
            }

            return ['version' => 1, 'group_id' => $group, 'genesis' => $s['genesis'], 'events' => $events, 'pending' => $p];
        }, 3);
    }

    public function invitations(Request $r, ?string $after): array
    {
        return DB::transaction(function () use ($r, $after) {
            $a = $this->locks($r, P::b64(str_repeat("\0", 16)));
            $rows = DB::table('membership_invites')->where('target_root', $a->rootFingerprint)->whereIn('state', ['pending', 'accepted'])->where('expires_at', '>', now())->when($after, fn ($q) => $q->where('id', '>', $after))->orderBy('id')->limit(21)->get();

            return ['version' => 1, 'invitations' => $rows->take(20)->map(fn ($r) => json_decode($r->signed_intent))->all(), 'next' => $rows->count() > 20 ? $rows[19]->id : null];
        }, 3);
    }

    /** Own-account API closure is distinct from signed membership and later physical retention. */
    public function closeAccount(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $a = $this->locks($r, P::b64(str_repeat("\0", 16)));
            D::require($a->recent && $body->account_id === $a->accountId && $body->root_fingerprint === $a->rootFingerprint, 'ROLE_FORBIDDEN');
            $ids = DB::table('group_memberships')->where('account_id', $a->accountId)->where('status', 'active')->orderBy('group_id')->pluck('group_id')->all();
            foreach ($ids as $id) {
                $g = DB::table('groups')->where('id', $id)->lockForUpdate()->first();
                // Resolve cryptographic ownership and leave through signed owner policy first.
                D::require($g && ($g->kind !== 'shared' || $g->state === 'purged'), 'ROLE_FORBIDDEN');
            }
            DB::table('account_closure_queue')->insert(['account_id' => $a->accountId, 'operation_id' => $body->operation_id, 'request_digest' => P::b64(hash('sha256', P::canonical($body), true)), 'requested_at' => now(), 'not_before' => now()->addDays(30), 'state' => 'pending-retention']);
            DB::table('users')->where('id', $a->accountId)->update(['status' => 'deleted']);
            foreach (DB::table('auth_sessions')->where('account_id', $a->accountId)->orderBy('id')->pluck('id') as $id) {
                Sessions::revoke($id);
            }
            DB::table('devices')->where('account_id', $a->accountId)->update(['status' => 'revoked']);
            DB::table('enrollment_sessions')->where('account_id', $a->accountId)->whereIn('state', ['pending', 'approved'])->update(['state' => 'cancelled']);
            $this->sync->append([['group_id' => null, 'audience_account_id' => $a->accountId, 'kind' => 'account-closure', 'object_id' => $a->accountId, 'revision_id' => null, 'digest' => P::b64(hash('sha256', P::canonical($body), true))]]);

            return ['version' => 1, 'operation_id' => $body->operation_id, 'state' => 'PENDING_RETENTION'];
        }, 3);
    }

    public function readReceipt(Request $r, string $operation, string $family): array
    {
        return DB::transaction(function () use ($r, $operation, $family) {
            $s = $this->sessions->current($r);
            $row = DB::table('group_security_receipts')->where('account_id', $s->account_id)->where('device_id', $s->device_id)->where('operation_id', $operation)->where('family', $family)->first();
            D::require($row !== null, 'NOT_FOUND');
            $a = $this->locks($r, $row->group_id);
            if ($family === 'accept' || $family === 'cancel') {
                $i = DB::table('membership_invites')->where('id', $operation)->where('group_id', $row->group_id)->first();
                $target = $i && $i->target_root === $a->rootFingerprint && json_decode($i->signed_intent)->body->target_account_id === $a->accountId;
                if (! $target) {
                    $this->auth->group($a, $row->group_id);
                }
            } else {
                $this->auth->group($a, $row->group_id);
            }

            return (array) json_decode($row->result);
        }, 3);
    }
}
