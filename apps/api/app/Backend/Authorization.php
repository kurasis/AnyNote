<?php

namespace App\Backend;

use App\Auth\Proof;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use Illuminate\Support\Facades\DB;
use stdClass;

/** Every entry reloads current durable authority, including on receipt retries. */
final class Authorization
{
    public function __construct(private P $protocol) {}

    public function actor(string $secret, bool $lock = true): Actor
    {
        if ($lock && DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
        if (strlen($secret) > 8192 || (! P::isBinary($secret, 32) && ! preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D', $secret))) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $session = DB::table('auth_sessions')->where('secret_hash', hash('sha256', $secret))->first();
        if (! $session) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $q = DB::table('users')->where('id', $session->account_id);
        $user = ($lock ? $q->lockForUpdate() : $q)->first();
        $q = DB::table('account_identities')->where('account_id', $session->account_id);
        $identity = ($lock ? $q->lockForUpdate() : $q)->first();
        $q = DB::table('auth_sessions')->where('id', $session->id);
        $session = ($lock ? $q->lockForUpdate() : $q)->first();
        if (! $user || $user->status !== 'active' || ! $session || $session->account_id !== $user->id || ! hash_equals($session->secret_hash, hash('sha256', $secret)) || $session->state === 'revoked' || $session->expires_at <= now()->format('Y-m-d H:i:s') || (isset($session->absolute_expires_at) && $session->absolute_expires_at <= now()->format('Y-m-d H:i:s'))) {
            throw new ApiException('SESSION_EXPIRED');
        }
        if ($session->state !== 'trusted') {
            throw new ApiException('SESSION_DEVICE_PROOF_REQUIRED');
        }
        $q = DB::table('devices')->where('account_id', $user->id)->where('id', $session->device_id);
        $device = ($lock ? $q->lockForUpdate() : $q)->first();
        if (! $device || $device->status === 'revoked') {
            throw new ApiException('DEVICE_REVOKED');
        }
        if ($device->status !== 'active') {
            throw new ApiException('DEVICE_NOT_TRUSTED');
        }
        if (! $identity || (string) $identity->recovery_generation !== (string) $session->recovery_generation || (string) $device->recovery_generation !== (string) $identity->recovery_generation) {
            throw new ApiException('DEVICE_REVOKED');
        }
        $root = $this->protocol->decode('p02-identity-c1', 'identity', $identity->identity_record);
        if ($root->body->account_id !== $user->id || $root->body->service_id !== config('api.service_id') || P::digest('p02-identity-c1', 'account-root-identity', $root->body) !== $identity->root_fingerprint) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        P::verify('p02-identity-c1', 'account-root-identity', $root->body, $root->signature, $root->body->root_signing_key);
        $cert = $this->certificate($device, $identity, $root, []);
        if (isset($session->device_commitment) && $session->device_commitment !== Proof::commitment(Proof::device($cert))) {
            throw new ApiException('DEVICE_REVOKED');
        }

        return new Actor($user->id, $device->id, $session->id, $identity->root_fingerprint, (string) $identity->recovery_generation, (string) $identity->roster_sequence, $identity->roster_digest, $cert->body->device_signing_key, $device->can_sign_content && in_array('sign-content', $cert->body->capabilities, true), (bool) $user->is_admin, $session->authenticated_at >= now()->subMinutes(5)->format('Y-m-d H:i:s'));
    }

    private function certificate(stdClass $device, stdClass $identity, stdClass $root, array $seen): stdClass
    {
        if (count($seen) >= 32 || isset($seen[$device->id])) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        $seen[$device->id] = true;
        $cert = $this->protocol->decode('p02-identity-c1', 'certificate', $device->certificate_record);
        $b = $cert->body;
        if ($b->service_id !== config('api.service_id') || $b->account_id !== $identity->account_id || $b->device_id !== $device->id || $b->root_fingerprint !== $identity->root_fingerprint || $b->recovery_generation !== (string) $identity->recovery_generation || $b->device_signing_key !== $device->signing_key || $b->device_encryption_key !== $device->encryption_key || P::digest('p02-identity-c1', 'device-certificate', $cert) !== $device->certificate_digest) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        $caps = $b->capabilities;
        $ordered = $caps;
        sort($ordered, SORT_STRING);
        if ($caps !== $ordered || $b->device_signing_key === $b->device_encryption_key || ($b->predecessor_roster === null && ($b->issuer->kind !== 'root' || $b->recovery_generation !== '0'))) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        $key = $root->body->root_signing_key;
        if ($b->issuer->kind === 'device') {
            $issuer = DB::table('devices')->where('account_id', $identity->account_id)->where('id', $b->issuer->device_id)->first();
            if (! $issuer || $issuer->status !== 'active' || $issuer->certificate_digest !== $b->issuer->certificate_digest) {
                throw new ApiException('INVALID_SIGNATURE');
            }
            $parent = $this->certificate($issuer, $identity, $root, $seen);
            if (! in_array('delegate-device', $parent->body->capabilities, true)) {
                throw new ApiException('INVALID_SIGNATURE');
            }
            $key = $parent->body->device_signing_key;
        } elseif ($b->issuer->root_fingerprint !== $identity->root_fingerprint) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        P::verify('p02-identity-c1', 'provisional-device-certificate', $b, $cert->signature, $key);

        return $cert;
    }

    /** Validate the active certified device before issuing a session-bound possession challenge. */
    public function certifiedDevice(string $account, string $device): array
    {
        if (DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
        $identity = DB::table('account_identities')->where('account_id', $account)->lockForUpdate()->first();
        $d = DB::table('devices')->where('account_id', $account)->where('id', $device)->lockForUpdate()->first();
        if (! $identity || ! $d || $d->status !== 'active' || (string) $d->recovery_generation !== (string) $identity->recovery_generation) {
            throw new ApiException('DEVICE_NOT_TRUSTED');
        }
        $root = $this->protocol->decode('p02-identity-c1', 'identity', $identity->identity_record);
        if ($root->body->account_id !== $account || $root->body->service_id !== config('api.service_id') || P::digest('p02-identity-c1', 'account-root-identity', $root->body) !== $identity->root_fingerprint) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        P::verify('p02-identity-c1', 'account-root-identity', $root->body, $root->signature, $root->body->root_signing_key);
        $cert = $this->certificate($d, $identity, $root, []);

        return [$identity, $d, $cert];
    }

    public function group(Actor $actor, string $id, string $permission = 'read', bool $lock = true): stdClass
    {
        if ($lock && DB::transactionLevel() < 1) {
            throw new \LogicException('Transaction required');
        }
        if (! in_array($permission, ['read', 'write', 'owner'], true)) {
            throw new ApiException('INVALID_REQUEST');
        }
        if (! P::isBinary($id, 16)) {
            throw new ApiException('NOT_FOUND');
        }
        $q = DB::table('groups')->where('id', $id);
        $group = ($lock ? $q->lockForUpdate() : $q)->first();
        $membership = DB::table('group_memberships')->where('group_id', $id)->where('account_id', $actor->accountId)->first();
        if (! $group || ! $membership || $membership->status !== 'active' || $group->state === 'purged') {
            throw new ApiException('NOT_FOUND');
        }
        if ($group->kind === 'private' && ($membership->role !== 'owner' || $group->owner_account_id !== $actor->accountId)) {
            throw new ApiException('NOT_FOUND');
        }
        if ($permission === 'owner' && ($membership->role !== 'owner' || $group->owner_account_id !== $actor->accountId)) {
            throw new ApiException('ROLE_FORBIDDEN');
        }
        if ($permission === 'write' && (! $actor->contentSigner || ! in_array($membership->role, ['owner', 'editor'], true))) {
            throw new ApiException('ROLE_FORBIDDEN');
        }
        if ($group->restore_quarantined) {
            throw new ApiException('RESTORE_QUARANTINE');
        }
        if ($permission === 'write') {
            if ($group->state !== 'active') {
                throw new ApiException('ROLE_FORBIDDEN');
            }
            if ($group->rekey_required) {
                throw new ApiException('REKEY_REQUIRED');
            }
            if ($group->history_closure_required) {
                throw new ApiException('HISTORY_CLOSURE_REQUIRED');
            }
        }

        return $group;
    }

    public function expected(Actor $a, stdClass $g, stdClass $c): void
    {
        if ($c->service_id !== config('api.service_id') || $c->group_id !== $g->id || $c->author->account_id !== $a->accountId || $c->author->device_id !== $a->deviceId || $c->author->root_fingerprint !== $a->rootFingerprint || $c->author->recovery_generation !== $a->generation) {
            throw new ApiException('INVALID_SIGNATURE');
        }
        if ($c->author->roster->version !== $a->rosterSequence || $c->author->roster->digest !== $a->rosterDigest) {
            throw new ApiException('ROSTER_CHANGED');
        }
        if ($c->policy->membership->version !== (string) $g->policy_sequence || $c->policy->membership->digest !== $g->policy_digest) {
            throw new ApiException('POLICY_CHANGED');
        }
        if ($c->policy->key_epoch !== (string) $g->epoch_number || $c->policy->epoch_digest !== $g->epoch_digest) {
            throw new ApiException('REKEY_REQUIRED');
        }
        if ($c->policy->history_checkpoint_digest !== $g->history_checkpoint_digest) {
            throw new ApiException('HISTORY_CLOSURE_REQUIRED');
        }
    }
}
