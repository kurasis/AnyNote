<?php

namespace App\Operations;

use App\Crypto\PublicProtocol as P;
use App\Devices\Protocol as D;
use App\Files\BlobStore;
use Illuminate\Support\Facades\DB;

/** Console-only, offline recovery source. Never grants restored network authority. */
final class Recovery
{
    public function quarantine(): array
    {
        D::require(app(RecoveryFence::class)->active(), 'RESTORE_QUARANTINE');

        return DB::transaction(function () {
            $counter = DB::table('sync_counters')->where('id', 1)->lockForUpdate()->first();
            $generation = P::b64(random_bytes(16));
            DB::table('sync_counters')->where('id', 1)->update(['generation' => $generation]);
            DB::table('operations_restore_state')->where('singleton', 1)->update(['quarantined' => true]);
            DB::table('groups')->update(['restore_quarantined' => true]);
            DB::table('auth_sessions')->update(['state' => 'revoked']);
            DB::table('refresh_tokens')->update(['state' => 'revoked']);
            DB::table('oauth_codes')->update(['revoked' => true]);
            DB::table('oauth_access')->update(['revoked' => true]);
            // Keep signed device/roster/policy history intact as evidence. The host
            // fence denies ALL restored credentials, including newer revocations
            // absent from this backup. No server mutation impersonates a root.
            foreach (['auth_challenges', 'auth_registrations', 'native_authorizations'] as $table) {
                DB::table($table)->update(['consumed_at' => now()]);
            }
            DB::table('enrollment_sessions')->update(['expires_at' => now()]);

            return ['status' => 'QUARANTINED', 'old_generation' => $counter->generation, 'new_generation' => $generation, 'online_content_access' => false];
        });
    }

    public function inventory(): array
    {
        $references = [];
        foreach (['file_chunks', 'upload_parts'] as $table) {
            foreach (DB::table($table)->orderBy('blob_id')->cursor() as $part) {
                app(BlobStore::class)->verify($part);
                $row = ['blob_id' => $part->blob_id, 'ciphertext_bytes' => (string) $part->ciphertext_bytes, 'digest' => $part->digest];
                D::require(! isset($references[$part->blob_id]) || $references[$part->blob_id] === $row, 'INVALID_CHUNK');
                $references[$part->blob_id] = $row;
            }
        }
        ksort($references, SORT_STRING);
        $orphans = 0;
        foreach (new \DirectoryIterator(app(BlobStore::class)->root()) as $entry) {
            if (! $entry->isDot()) {
                D::require(! $entry->isLink() && $entry->isFile() && P::isBinary($entry->getFilename(), 16), 'INVALID_CHUNK');
                $orphans += (int) ! isset($references[$entry->getFilename()]);
            }
        }
        $missing = DB::table('attachment_refs as a')->leftJoin('file_versions as f', 'a.file_version_id', '=', 'f.id')->whereNull('f.id')->exists();
        D::require(! $missing, 'INVALID_CHUNK');
        D::require(! DB::table('object_revisions as r')->leftJoin('object_key_wraps as w', 'r.revision_id', '=', 'w.revision_id')->where('r.payload_status', 'retained')->whereNull('w.wrap_record')->exists(), 'INVALID_CHUNK');
        D::require(! DB::table('key_envelopes as k')->leftJoin('group_key_epochs as e', function ($join) {
            $join->on('k.group_id', '=', 'e.group_id')->on('k.epoch_number', '=', 'e.epoch_number');
        })->whereNull('e.id')->exists(), 'INVALID_CHUNK');
        foreach (DB::table('account_identities')->orderBy('account_id')->cursor() as $identity) {
            D::require(DB::table('account_roster_events')->where('account_id', $identity->account_id)->where('sequence', $identity->roster_sequence)->where('digest', $identity->roster_digest)->exists(), 'INVALID_SIGNATURE');
        }
        foreach (DB::table('file_versions')->where('state', 'committed')->orderBy('id')->cursor() as $version) {
            $manifest = json_decode($version->manifest_record);
            D::require(isset($manifest->envelope->header->framing), 'INVALID_CHUNK');
            $parts = $manifest->envelope->header->framing->parts;
            $chunks = DB::table('file_chunks')->where('file_version_id', $version->id)->orderBy('chunk_index')->get();
            D::require(count($parts) === count($chunks), 'INVALID_CHUNK');
            foreach ($chunks as $index => $chunk) {
                D::require((int) $chunk->chunk_index === $index && $parts[$index]->ciphertext_digest === $chunk->digest && $parts[$index]->ciphertext_bytes === (string) $chunk->ciphertext_bytes, 'INVALID_CHUNK');
            }
        }
        $tables = [];
        foreach (DB::select('SHOW TABLES') as $table) {
            $name = array_values((array) $table)[0];
            $tables[$name] = DB::table($name)->count();
        }
        ksort($tables);

        return ['version' => 1, 'generation' => DB::table('sync_counters')->value('generation'), 'sequence' => (string) DB::table('sync_counters')->value('sequence'), 'tables' => $tables, 'blobs' => array_values($references), 'unreferenced_opaque_blobs' => $orphans, 'reference_reconciliation' => 'PASS'];
    }

    public function catalogue(string $group): array
    {
        D::require(app(RecoveryFence::class)->active() && P::isBinary($group, 16), 'RESTORE_QUARANTINE');
        $g = DB::table('groups')->where('id', $group)->first();
        D::require($g && $g->restore_quarantined && $g->kind === 'private' && (int) $g->epoch_number === 0, 'UNSUPPORTED_SCHEMA');
        $i = DB::table('account_identities')->where('account_id', $g->owner_account_id)->first();
        $genesis = DB::table('private_group_geneses')->where('group_id', $group)->first();
        D::require($genesis && DB::table('object_revisions')->where('group_id', $group)->count() <= 1000, 'RESOURCE_LIMIT');
        $records = [];
        $metadataBytes = 0;
        D::require(DB::table('account_roster_events')->where('account_id', $i->account_id)->count() <= 10000 && (int) DB::table('account_roster_events')->where('account_id', $i->account_id)->sum(DB::raw('OCTET_LENGTH(signed_record)')) <= 8388608, 'RESOURCE_LIMIT');
        foreach (DB::table('object_revisions')->where('group_id', $group)->where('payload_status', 'retained')->orderBy('revision_id')->cursor() as $r) {
            $metadataBytes += (int) ceil(strlen($r->ciphertext) * 4 / 3) + strlen($r->signed_envelope) + 4096;
            D::require($metadataBytes <= 16777216, 'RESOURCE_LIMIT');
            $records[] = ['envelope' => json_decode($r->signed_envelope), 'ciphertext' => P::b64($r->ciphertext), 'wrap' => json_decode(DB::table('object_key_wraps')->where('revision_id', $r->revision_id)->value('wrap_record'))];
        }
        $files = [];
        foreach (DB::table('file_versions')->where('group_id', $group)->where('state', 'committed')->orderBy('id')->cursor() as $f) {
            D::require(count($files) < 32, 'RESOURCE_LIMIT');
            $files[] = ['record' => json_decode($f->manifest_record), 'chunks' => DB::table('file_chunks')->where('file_version_id', $f->id)->orderBy('chunk_index')->get(['blob_id', 'digest', 'ciphertext_bytes'])->all()];
        }
        D::require(strlen(json_encode($records)) <= 16777216, 'RESOURCE_LIMIT');

        return ['version' => 1, 'purpose' => 'offline-private-genesis-recovery', 'pins' => ['service_id' => config('api.service_id'), 'account_id' => $i->account_id, 'root_fingerprint' => $i->root_fingerprint], 'snapshot' => ['identity' => json_decode($i->identity_record), 'head' => ['version' => (string) $i->roster_sequence, 'digest' => $i->roster_digest], 'generation' => (string) $i->recovery_generation, 'events' => DB::table('account_roster_events')->where('account_id', $i->account_id)->orderBy('sequence')->pluck('signed_record')->map(fn ($r) => json_decode($r))->all()], 'genesis' => ['commit' => json_decode($genesis->commit_record), 'pages' => [json_decode($genesis->grant_page)]], 'records' => $records, 'files' => $files];
    }
}
