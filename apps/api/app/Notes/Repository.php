<?php

namespace App\Notes;

use App\Auth\Sessions;
use App\Backend\Actor;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol;
use App\Devices\Settings;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Current account-private authorization and bounded public/ciphertext reads. */
final class Repository
{
    public function __construct(private Sessions $sessions, private Authorization $authorization) {}

    public function actor(Request $r): Actor
    {
        $this->sessions->current($r, true);

        return $this->authorization->actor($this->sessions->secret($r));
    }

    public function group(Actor $a, string $id, string $permission = 'read'): stdClass
    {
        $g = $this->authorization->group($a, $id, $permission);
        Protocol::require($g->kind !== 'shared' || DB::table('shared_group_geneses')->where('group_id', $id)->exists(), 'NOT_FOUND');

        return $g;
    }

    public function status(Actor $a, stdClass $g): array
    {
        $settings = DB::table('account_settings_genesis')->where('group_id', $g->id)->first();
        $row = $settings ?? DB::table($g->kind === 'shared' ? 'shared_group_geneses' : 'private_group_geneses')->where('group_id', $g->id)->first();
        Protocol::require($row !== null && ($g->kind === 'shared' || $row->account_id === $a->accountId), 'NOT_FOUND');

        return ['version' => 1, 'group_id' => $g->id, 'kind' => $g->kind, 'owner_account_id' => $g->owner_account_id, 'state' => $g->state, 'membership' => ['version' => (string) $g->policy_sequence, 'digest' => $g->policy_digest], 'key_epoch' => (string) $g->epoch_number, 'epoch_digest' => $g->epoch_digest, 'history_checkpoint_digest' => $g->history_checkpoint_digest, 'rekey_required' => (bool) $g->rekey_required, 'history_closure_required' => (bool) $g->history_closure_required, 'restore_quarantined' => (bool) $g->restore_quarantined, 'settings' => $settings !== null, 'genesis' => ['version' => 1, 'group_id' => $g->id, 'commit' => json_decode($row->commit_record), 'pages' => [json_decode($row->grant_page)]]];
    }

    public function create(Request $r, stdClass $body): array
    {
        return DB::transaction(function () use ($r, $body) {
            $result = app(Settings::class)->create($r, $body, false, $body->commit->body->policy->body->payload->group_kind);
            $a = $this->actor($r);

            return $this->status($a, $this->group($a, $result['group_id']));
        }, 3);
    }

    public function groups(Request $r, ?string $after): array
    {
        return DB::transaction(function () use ($r, $after) {
            $a = $this->actor($r);
            $q = DB::table('groups')->whereIn('id', DB::table('group_memberships')->select('group_id')->where('account_id', $a->accountId)->where('status', 'active'))->whereIn('state', ['active', 'archived'])->orderBy('id');
            if ($after !== null) {
                $q->where('id', '>', $after);
            }
            $rows = $q->limit(21)->get();
            $items = [];
            $bytes = 128;
            $next = null;
            foreach ($rows as $row) {
                $item = $this->status($a, $this->group($a, $row->id));
                $size = strlen(json_encode($item, JSON_THROW_ON_ERROR)) + 1;
                if (count($items) >= 20 || $bytes + $size > 1048576) {
                    $next = $items[count($items) - 1]['group_id'];
                    break;
                }
                $items[] = $item;
                $bytes += $size;
            }

            return ['version' => 1, 'groups' => $items, 'next' => $next];
        }, 3);
    }

    public function one(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $a = $this->actor($r);

            return $this->status($a, $this->group($a, $id));
        }, 3);
    }

    public function object(Actor $a, string $id): stdClass
    {
        $o = DB::table('objects')->where('id', $id)->first();
        Protocol::require($o !== null, 'NOT_FOUND');
        $this->group($a, $o->group_id);

        return $o;
    }

    public function reference(stdClass $o): array
    {
        $heads = DB::table('object_heads as h')->join('object_revisions as r', 'h.revision_id', '=', 'r.revision_id')->where('h.object_id', $o->id)->orderBy('h.revision_id')->get(['h.revision_id', 'r.envelope_digest']);
        Protocol::require($heads->count() <= 32, 'RESOURCE_LIMIT');

        return ['object_id' => $o->id, 'object_kind' => $o->kind, 'thread_id' => $o->thread_id, 'archived' => (bool) $o->archived, 'tombstoned' => (bool) $o->tombstoned, 'created_sequence' => (string) $o->created_sequence, 'updated_sequence' => (string) $o->updated_sequence, 'heads' => $heads->map(fn ($h) => ['revision_id' => $h->revision_id, 'envelope_digest' => $h->envelope_digest])->all()];
    }

    public function objects(Request $r, string $id, string $mode, ?string $after): array
    {
        return DB::transaction(function () use ($r, $id, $mode, $after) {
            $a = $this->actor($r);
            $thread = null;
            if ($mode === 'entries') {
                $t = $this->object($a, $id);
                Protocol::require($t->kind === 'thread', 'NOT_FOUND');
                $group = $t->group_id;
                $thread = $id;
            } else {
                $this->group($a, $id);
                $group = $id;
            }
            $q = DB::table('objects')->where('group_id', $group);
            $q->orderBy($mode === 'entries' ? 'created_sequence' : 'id');
            if ($mode === 'entries') {
                $q->where('kind', 'entry')->where('thread_id', $thread)->where('tombstoned', false);
            } elseif ($mode === 'threads') {
                $q->where('kind', 'thread')->where('tombstoned', false);
            } else {
                $q->where('tombstoned', true);
            }
            if ($after !== null) {
                $q->where($mode === 'entries' ? 'created_sequence' : 'id', '>', $after);
            }
            $rows = $q->limit(101)->get();
            $more = $rows->count() > 100;
            $rows = $rows->take(100);

            return ['version' => 1, 'group_id' => $group, 'thread_id' => $thread, 'objects' => $rows->map(fn ($o) => $this->reference($o))->all(), 'next' => $more ? ($mode === 'entries' ? (string) $rows->last()->created_sequence : $rows->last()->id) : null];
        }, 3);
    }

    public function state(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $a = $this->actor($r);
            $o = $this->object($a, $id);

            return ['version' => 1, 'group_id' => $o->group_id, 'object' => $this->reference($o)];
        }, 3);
    }

    public function revisions(Request $r, string $id, ?string $after): array
    {
        return DB::transaction(function () use ($r, $id, $after) {
            $a = $this->actor($r);
            $o = $this->object($a, $id);
            $q = DB::table('object_revisions')->where('group_id', $o->group_id)->where('object_id', $id)->orderBy('revision_id');
            if ($after !== null) {
                $q->where('revision_id', '>', $after);
            }
            $rows = $q->limit(101)->get(['revision_id', 'envelope_digest', 'ciphertext_bytes']);
            $more = $rows->count() > 100;
            $rows = $rows->take(100);

            return ['version' => 1, 'group_id' => $o->group_id, 'object_id' => $id, 'revisions' => $rows->map(fn ($x) => ['revision_id' => $x->revision_id, 'envelope_digest' => $x->envelope_digest, 'ciphertext_bytes' => (string) $x->ciphertext_bytes])->all(), 'next' => $more ? $rows->last()->revision_id : null];
        }, 3);
    }

    public function bundle(Request $r, string $id, string $revision): array
    {
        return DB::transaction(function () use ($r, $id, $revision) {
            $a = $this->actor($r);
            $o = $this->object($a, $id);
            $row = DB::table('object_revisions')->where('group_id', $o->group_id)->where('object_id', $id)->where('revision_id', $revision)->first();
            $wrap = DB::table('object_key_wraps')->where('revision_id', $revision)->first();
            Protocol::require($row !== null && $wrap !== null, 'NOT_FOUND');

            return ['version' => 1, 'group_id' => $o->group_id, 'object_id' => $id, 'revision_id' => $revision, 'bundle' => ['envelope' => json_decode($row->signed_envelope), 'wrap' => json_decode($wrap->wrap_record), 'ciphertext' => P::b64($row->ciphertext)]];
        }, 3);
    }
}
