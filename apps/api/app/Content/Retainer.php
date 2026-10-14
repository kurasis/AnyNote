<?php

namespace App\Content;

use App\Backend\QuotaLedger;
use App\Backend\SyncWriter;
use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Reference-safe payload compaction. Signed ancestry and tombstone headers survive. */
final class Retainer
{
    public function __construct(private QuotaLedger $quota, private SyncWriter $sync) {}

    private function reasons(stdClass $revision, array $daily, array $monthly): array
    {
        $reasons = [];
        if (DB::table('object_heads')->where('revision_id', $revision->revision_id)->exists()) {
            $reasons[] = 'current-or-conflict-head';
        }
        if (DB::table('content_retention_pins')->where('revision_id', $revision->revision_id)->exists()) {
            $reasons[] = 'explicit-retention-pin';
        }
        if (DB::table('reference_pins as p')->join('snapshot_sessions as s', 'p.snapshot_id', '=', 's.id')->where('p.revision_id', $revision->revision_id)->where('s.state', 'active')->where('s.expires_at', '>', gmdate('Y-m-d H:i:s'))->exists()) {
            $reasons[] = 'active-snapshot-or-export';
        }
        $object = DB::table('objects')->where('id', $revision->object_id)->first();
        $committed = strtotime($revision->committed_at.' UTC');
        $age = now()->timestamp - $committed;
        if ($object->tombstoned && ($object->trash_expires_at === null || $object->trash_expires_at > now()->format('Y-m-d H:i:s'))) {
            $reasons[] = 'retained-trash';
        }
        if ($age < 2592000) {
            $reasons[] = 'latest-thirty-days';
        } elseif ($age < 10368000 && ($daily[$revision->object_id.'/'.gmdate('Y-m-d', $committed)] ?? null) === $revision->revision_id) {
            $reasons[] = 'daily-ninety-days';
        } elseif ($age >= 10368000 && ($monthly[$revision->object_id.'/'.gmdate('Y-m', $committed)] ?? null) === $revision->revision_id) {
            $reasons[] = 'monthly-history';
        }

        return $reasons;
    }

    public function run(string $group, int $limit = 100, bool $apply = false, ?string $after = null): array
    {
        D::require(P::isBinary($group, 16) && $limit >= 1 && $limit <= 100 && ($after === null || P::isBinary($after, 16)), 'INVALID_REQUEST');

        return DB::transaction(function () use ($group, $limit, $apply, $after) {
            $hint = DB::table('groups')->where('id', $group)->first();
            D::require($hint !== null, 'NOT_FOUND');
            // Account/security, common collector boundary, sorted group, quota, counter last.
            DB::table('users')->where('id', $hint->owner_account_id)->lockForUpdate()->first();
            DB::table('gc_coordination')->where('singleton', 1)->lockForUpdate()->first();
            DB::table('groups')->where('id', $group)->lockForUpdate()->first();
            $revisions = DB::table('object_revisions')->where('group_id', $group)->where('payload_status', 'retained')->orderBy('committed_at', 'desc')->orderBy('revision_id', 'desc')->limit(50001)->get();
            D::require($revisions->count() <= 50000, 'RESOURCE_LIMIT');
            $daily = [];
            $monthly = [];
            foreach ($revisions as $revision) {
                $time = strtotime($revision->committed_at.' UTC');
                $daily[$revision->object_id.'/'.gmdate('Y-m-d', $time)] ??= $revision->revision_id;
                $monthly[$revision->object_id.'/'.gmdate('Y-m', $time)] ??= $revision->revision_id;
            }
            $items = [];
            $events = [];
            $released = 0;
            $ordered = $revisions->sortBy('revision_id')->values();
            if ($after !== null) {
                $ordered = $ordered->filter(fn ($r) => strcmp($r->revision_id, $after) > 0)->values();
            }
            foreach ($ordered->take($limit) as $revision) {
                $reasons = $this->reasons($revision, $daily, $monthly);
                $items[] = ['revision_id' => $revision->revision_id, 'object_id' => $revision->object_id, 'payload_status' => 'retained', 'eligible' => $reasons === [], 'reasons' => $reasons];
                if ($apply && $reasons === []) {
                    $ledgers = $this->quota->lock($revision->author_account_id, $group);
                    $locked = DB::table('object_revisions')->where('revision_id', $revision->revision_id)->lockForUpdate()->first();
                    if ($locked->payload_status !== 'retained') {
                        continue;
                    }
                    $wrap = DB::table('object_key_wraps')->where('revision_id', $revision->revision_id)->lockForUpdate()->first();
                    $bytes = (int) $locked->ciphertext_bytes + (int) $wrap->ciphertext_bytes;
                    DB::table('object_revisions')->where('revision_id', $revision->revision_id)->update(['ciphertext' => null, 'ciphertext_bytes' => 0, 'payload_status' => 'pruned', 'payload_pruned_at' => now()]);
                    DB::table('object_key_wraps')->where('revision_id', $revision->revision_id)->update(['wrap_record' => null, 'ciphertext_bytes' => 0]);
                    DB::table('attachment_refs')->where('revision_id', $revision->revision_id)->delete();
                    $this->quota->apply($ledgers, -$bytes, 0);
                    $released += $bytes;
                    $items[count($items) - 1]['payload_status'] = 'pruned';
                    $events[] = ['group_id' => $group, 'kind' => 'payload-prune', 'object_id' => $revision->object_id, 'revision_id' => null, 'digest' => $revision->envelope_digest];
                }
            }
            if ($events !== []) {
                $this->sync->append($events);
            }

            return ['version' => 1, 'group_id' => $group, 'mode' => $apply ? 'explicit-apply' : 'report-only', 'items' => $items, 'next' => $ordered->count() > $limit ? $items[count($items) - 1]['revision_id'] : null, 'released_ciphertext_bytes' => (string) $released, 'signed_ancestry_retained' => true, 'physical_database_pages_reclaimed' => false];
        }, 3);
    }
}
