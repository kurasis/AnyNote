<?php

namespace App\Backend;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;

final class ScopedRepository
{
    public function __construct(private Authorization $authorization) {}

    public function revisions(string $secret, string $groupId, string $objectId, ?string $after = null, int $limit = 20): array
    {
        if ($limit < 1 || $limit > 100 || ! P::isBinary($objectId, 16) || ($after !== null && ! P::isBinary($after, 16))) {
            throw new ApiException('INVALID_REQUEST');
        }

        return DB::transaction(function () use ($secret, $groupId, $objectId, $after, $limit) {
            $a = $this->authorization->actor($secret);
            $this->authorization->group($a, $groupId);
            if (! DB::table('objects')->where('group_id', $groupId)->where('id', $objectId)->exists()) {
                throw new ApiException('NOT_FOUND');
            }
            $query = DB::table('object_revisions')->where('group_id', $groupId)->where('object_id', $objectId)->orderBy('revision_id');
            if ($after !== null) {
                $query->where('revision_id', '>', $after);
            }
            $result = [];
            $size = 2;
            // Fetch only references, never an unbounded collection of encrypted notes.
            foreach ($query->limit($limit)->get(['revision_id', 'envelope_digest', 'ciphertext_bytes']) as $row) {
                $item = ['revision_id' => $row->revision_id, 'envelope_digest' => $row->envelope_digest, 'ciphertext_bytes' => (string) $row->ciphertext_bytes];
                $size += strlen(json_encode($item, JSON_THROW_ON_ERROR)) + 1;
                if ($size > 1048576) {
                    throw new ApiException('RESOURCE_LIMIT');
                }
                $result[] = $item;
            }

            return $result;
        }, 3);
    }

    public function receipt(string $secret, string $operationId): array
    {
        if (! P::isBinary($operationId, 16)) {
            throw new ApiException('NOT_FOUND');
        }

        return DB::transaction(function () use ($secret, $operationId) {
            $a = $this->authorization->actor($secret);
            $r = DB::table('mutation_receipts')->where('account_id', $a->accountId)->where('device_id', $a->deviceId)->where('operation_id', $operationId)->first();
            if (! $r || $r->expires_at <= now()->format('Y-m-d H:i:s')) {
                throw new ApiException('NOT_FOUND');
            }
            $this->authorization->group($a, $r->group_id);

            return json_decode($r->result, true, 32, JSON_THROW_ON_ERROR);
        }, 3);
    }
}
