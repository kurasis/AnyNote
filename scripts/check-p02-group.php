<?php
// Independent PUBLIC ASCII fixture subset only. No general parser/JCS/schema,
// account login, physical witness, SQL or production authorization implementation.
declare(strict_types=1);
ob_start(); require __DIR__.'/check-p02-state.php'; ob_end_clean();
$checks = 0;
function groupDomain(string $family, string $purpose): string { return "AnyNote/p02-group-c1/$family/$purpose\0"; }
function groupHash(string $kind, mixed $record): string { return b64(hash('sha256', groupDomain('hash', $kind).fixtureCanonical($record), true)); }
function groupInput(object $body): string { return groupDomain('sign', $body->purpose).fixtureCanonical($body); }
function groupSignature(object $record, string $key): void {
    must(sodium_crypto_sign_verify_detached(un64($record->signature), groupInput($record->body), un64($key)));
    $bad = un64($record->signature); $bad[0] = chr(ord($bad[0]) ^ 1);
    must(!sodium_crypto_sign_verify_detached($bad, groupInput($record->body), un64($key)));
}
function seedBytes(int $start, int $length = 32): string { $bytes = ''; for ($i = 0; $i < $length; ++$i) $bytes .= chr(($start + $i) % 256); return $bytes; }
function certDigest(object $cert): string { return b64(hash('sha256', domain('hash', 'device-certificate').fixtureCanonical($cert), true)); }
function accountEvent(array &$account, object $event, int $deviceIndex): void {
    $b = $event->body; $p = $b->payload;
    must(fixtureCanonical($b->predecessor) === fixtureCanonical($account['head']));
    must($b->version === (string) ($account['head'] === null ? 0 : (int) $account['head']->version + 1));
    if ($b->kind === 'register' || $b->kind === 'reset') {
        stateSignature($event, $account['identity']->body->root_signing_key);
        secretProof($p->challenge, $p->confirmation, $deviceIndex);
        $cert = $p->certificate; $issuer = $account['identity']->body->root_signing_key;
        if ($b->kind === 'reset') foreach ($account['devices'] as &$device) $device['status'] = 'REVOKED'; unset($device);
    } else {
        must($b->kind === 'enroll'); $parent = $p->transcript->response->body->approver->device_id;
        must($account['devices'][$parent]['status'] === 'ACTIVE'); $issuer = $account['devices'][$parent]['cert']->body->device_signing_key;
        stateSignature($p->approval, $issuer); stateSignature($p->transcript->response, $issuer);
        stateSignature($p->transcript->offer, $p->transcript->offer->body->device->signing_key);
        stateSignature($p->confirmation, $p->transcript->offer->body->device->signing_key);
        stateSignature($event, $p->transcript->offer->body->device->signing_key);
        $plain = sodium_crypto_box_seal_open(un64($p->approval->body->sealed_challenge), devicePair($deviceIndex)); must($plain !== false);
        $proof = json_decode($plain, false, 32, JSON_THROW_ON_ERROR);
        must(stateHash('pairing-proof-plaintext', $proof) === $p->approval->body->challenge_digest && $proof->secret === $p->confirmation->body->challenge_response);
        sodium_memzero($plain); $cert = $p->approval->body->certificate;
    }
    must(sodium_crypto_sign_verify_detached(un64($cert->signature), signInput('provisional-device-certificate', $cert->body), un64($issuer)));
    $account['devices'][$cert->body->device_id] = ['cert' => $cert, 'status' => 'ACTIVE', 'index' => $deviceIndex];
    $account['generation'] = $b->generation; $account['head'] = (object) ['version' => $b->version, 'digest' => stateHash('event', $event)];
}
function senderCheck(object $sender, array $accounts): object {
    $a = $accounts[$sender->account_id]; $d = $a['devices'][$sender->device_id]; must($d['status'] === 'ACTIVE');
    must($sender->root_fingerprint === $a['pin']->root_fingerprint && $sender->recovery_generation === $a['generation']);
    must(fixtureCanonical($sender->roster_head) === fixtureCanonical($a['head']) && $sender->certificate_digest === certDigest($d['cert'])); return $d['cert'];
}
function rosterList(array $members, array $accounts): array {
    $list = []; foreach ($members as $member) { $a = $accounts[$member->account_id]; must($member->root_fingerprint === $a['pin']->root_fingerprint); $list[] = (object) ['account_id' => $member->account_id, 'root_fingerprint' => $member->root_fingerprint, 'recovery_generation' => $a['generation'], 'roster' => $a['head']]; }
    usort($list, fn($a, $b) => strcmp($a->account_id, $b->account_id)); return $list;
}
function inventoryHash(string $family, string $purpose, array $pages, int $records, callable $pageHash): string {
    $input = ($family === 'group' ? groupDomain('hash', $purpose) : fileDomain('hash', $purpose)).pack('N3', count($pages), 0, $records);
    foreach ($pages as $i => $page) { must($page->page_index === (string) $i); $input .= pack('N3', $i, count($page->records), strlen(fixtureCanonical($page))).un64($pageHash($page)); }
    return b64(hash('sha256', $input, true));
}
$f = json_decode(file_get_contents($argv[3]), false, 32, JSON_THROW_ON_ERROR); $accounts = [];
foreach ($f->inputs->accounts as $index => $input) {
    $context = clone $fixture->input->context; $context->account_id = $input->pin->account_id;
    $r = $index === 0 ? hex2bin($fixture->input->root_secret_hex) : seedBytes($index === 1 ? 80 : 160);
    $jcs = fixtureCanonical($context); $salt = hash('sha256', domain('hkdf', 'extract-salt').$jcs, true);
    $signSeed = hash_hkdf('sha256', $r, 32, domain('hkdf', 'root-signing-seed').$jcs, $salt);
    $boxSeed = hash_hkdf('sha256', $r, 32, domain('hkdf', 'recovery-encryption-seed').$jcs, $salt);
    $signPair = sodium_crypto_sign_seed_keypair($signSeed); $boxPair = sodium_crypto_box_seed_keypair($boxSeed);
    must(b64(sodium_crypto_sign_publickey($signPair)) === $input->identity->body->root_signing_key);
    must(b64(sodium_crypto_box_publickey($boxPair)) === $input->identity->body->recovery_encryption_key);
    must(b64(hash('sha256', domain('hash', 'account-root-identity').fixtureCanonical($input->identity->body), true)) === $input->pin->root_fingerprint);
    must(sodium_crypto_sign_verify_detached(un64($input->identity->signature), signInput('account-root-identity', $input->identity->body), sodium_crypto_sign_publickey($signPair)));
    $a = ['identity' => $input->identity, 'pin' => $input->pin, 'head' => null, 'generation' => '0', 'devices' => [], 'recovery' => $boxPair];
    foreach ($input->events as $event) accountEvent($a, $event, $index * 4); $accounts[$input->pin->account_id] = $a;
}
$genesis = $f->inputs->genesis; $scope = (object) ['service_id' => $genesis->body->service_id, 'group_id' => $genesis->body->group_id];
$cert = senderCheck($genesis->body->signer, $accounts); groupSignature($genesis, $cert->body->device_signing_key);
must(groupHash('policy', $genesis) === $f->inputs->genesis_pin->genesis_digest);
$members = $genesis->body->members; $policy = (object) ['version' => '0', 'digest' => groupHash('policy', $genesis)];
$epoch = null; $epochRows = []; $epochRosters = null; $history = null; $historyDigest = null; $observed = []; $historyRequired = false; $historyKnown = false; $removalRekey = false; $archived = false; $grants = 0; $epochs = 0; $policies = 1; $checkpoints = 0;
foreach ($f->inputs->steps as $step) {
    if ($step->kind === 'account-event') {
        $accountId = $f->inputs->accounts[$step->account_index]->pin->account_id;
        accountEvent($accounts[$accountId], $step->record, $step->record->body->kind === 'reset' ? 10 : 9);
    } elseif ($step->kind === 'policy' || ($step->kind === 'epoch' && $step->record->body->policy !== null)) {
        $p = $step->kind === 'policy' ? $step->record : $step->record->body->policy; $b = $p->body;
        must(fixtureCanonical($b->predecessor) === fixtureCanonical($policy) && $b->version === (string) ((int) $policy->version + 1));
        $actor = senderCheck($b->signer, $accounts); must(array_values(array_filter($members, fn($m) => $m->role === 'owner'))[0]->account_id === $b->signer->account_id); groupSignature($p, $actor->body->device_signing_key);
        if ($b->action === 'transfer') { $incoming = senderCheck($b->payload->incoming_signer, $accounts); must(sodium_crypto_sign_verify_detached(un64($p->cosignature), groupInput($b), un64($incoming->body->device_signing_key))); }
        else must($p->cosignature === null);
        if ($b->action === 'admit') {
            $i = $b->payload->invitation; $a = $b->payload->acceptance; groupSignature($i, $actor->body->device_signing_key);
            $target = senderCheck($a->body->signer, $accounts); groupSignature($a, $target->body->device_signing_key);
            must($i->body->full_retained_history && $a->body->full_retained_history && $a->body->invitation_digest === groupHash('invitation', $i));
            must($target->body->account_id === $i->body->target_account_id && $target->body->root_fingerprint === $i->body->target_root_fingerprint);
        }
        if ($b->action === 'remove') { $removalRekey = true; $historyRequired = true; }
        if ($b->action === 'role' && $b->payload->role === 'reader') $historyRequired = true;
        if ($b->action === 'archive') $archived = true; if ($b->action === 'unarchive') $archived = false;
        $members = $b->members; must(count(array_filter($members, fn($m) => $m->role === 'owner')) === 1);
        $policy = (object) ['version' => $b->version, 'digest' => groupHash('policy', $p)]; ++$policies;
    }
    if ($step->kind === 'epoch') {
        $commit = $step->record; $intent = $commit->body->intent; $b = $intent->body; $descriptor = $commit->body->descriptor; $d = $descriptor->body;
        $actor = senderCheck($b->signer, $accounts); groupSignature($intent, $actor->body->device_signing_key); groupSignature($commit, $actor->body->device_signing_key); groupSignature($descriptor, $actor->body->device_signing_key);
        must(fixtureCanonical($b->membership) === fixtureCanonical($policy) && fixtureCanonical($b->previous_epoch) === fixtureCanonical($epoch));
        must(fixtureCanonical($b->rosters) === fixtureCanonical(rosterList($members, $accounts)) && fixtureCanonical($b->retained_epochs) === fixtureCanonical($epochRows));
        must($b->next_epoch === (string) count($epochRows) && $b->history_checkpoint_digest === $historyDigest);
        $rows = [...$epochRows, (object) ['key_epoch' => $b->next_epoch, 'epoch_digest' => groupHash('epoch-intent', $intent), 'key_commitment' => $b->key_commitment]];
        $count = array_sum(array_map(fn($p) => count($p->records), $step->pages));
        must($d->record_count === (string) $count && $d->page_count === (string) count($step->pages));
        must($d->inventory_digest === inventoryHash('group', 'grant-inventory', $step->pages, $count, fn($page) => groupHash('grant-page', $page)));
        must($d->epoch_inventory_digest === groupHash('epochs', $rows) && $d->intent_digest === groupHash('epoch-intent', $intent));
        $expected = [];
        foreach ($rows as $row) foreach ($members as $member) {
            $a = $accounts[$member->account_id];
            $rs = [(object) ['kind' => 'account-recovery', 'account_id' => $member->account_id, 'root_fingerprint' => $member->root_fingerprint, 'recovery_generation' => $a['generation'], 'roster_head' => $a['head'], 'encryption_key_fingerprint' => b64(hash('sha256', domain('hash', 'x25519-public-key').sodium_crypto_box_publickey($a['recovery']), true))]];
            $pairs = [$a['recovery']];
            foreach ($a['devices'] as $id => $device) if ($device['status'] === 'ACTIVE') {
                $cert = $device['cert']; $rs[] = (object) ['kind' => 'device', 'account_id' => $member->account_id, 'device_id' => $id, 'root_fingerprint' => $member->root_fingerprint, 'recovery_generation' => $a['generation'], 'roster_head' => $a['head'], 'certificate_digest' => certDigest($cert), 'encryption_key_fingerprint' => b64(hash('sha256', domain('hash', 'x25519-public-key').un64($cert->body->device_encryption_key), true))]; $pairs[] = devicePair($device['index']);
            }
            foreach ($rs as $i => $recipient) {
                $ctx = (object) ['purpose' => 'group-key-distribution', 'contract' => 'p02-identity-c1', 'protocol' => 'anynote', 'protocol_version' => 1, 'service_id' => $scope->service_id, 'group_id' => $scope->group_id, 'key_epoch' => $row->key_epoch, 'epoch_digest' => $row->epoch_digest, 'membership_head' => $policy, 'operation_id' => $b->operation_id, 'issuer' => $b->signer, 'recipient' => $recipient];
                $expected[fixtureCanonical($ctx)] = [$row, $pairs[$i]];
            }
        }
        must(count($expected) === $count);
        foreach ($step->pages as $page) foreach ($page->records as $grant) {
            $ctx = fixtureCanonical($grant->body->context); must(isset($expected[$ctx])); [$row, $pair] = $expected[$ctx]; unset($expected[$ctx]);
            must(sodium_crypto_sign_verify_detached(un64($grant->signature), signInput('group-key-distribution', $grant->body), un64($actor->body->device_signing_key)));
            $plain = sodium_crypto_box_seal_open(un64($grant->body->sealed_ciphertext), $pair); must($plain !== false); $decoded = json_decode($plain, false, 32, JSON_THROW_ON_ERROR);
            must(fixtureCanonical($decoded->context) === $ctx && un64($decoded->group_key) === seedBytes(120 + (int) $row->key_epoch * 7));
            must(b64(hash('sha256', groupDomain('hash', 'group-epoch-key').fixtureCanonical($scope).un64($decoded->group_key), true)) === $row->key_commitment);
            sodium_memzero($plain); ++$grants;
        }
        must(count($expected) === 0);
        if ($b->reason === 'roster-maintenance') $historyRequired = true;
        $epochRows = $rows; $epochRosters = $b->rosters; $epoch = (object) ['version' => $b->next_epoch, 'digest' => groupHash('epoch-commit', $commit)]; $removalRekey = false; ++$epochs;
    } elseif ($step->kind === 'fresh-history') {
        must($policy->version === '0' && $epoch->version === '0' && $history === null && !$observed);
        $historyKnown = true;
    } elseif ($step->kind === 'file') {
        $env = $step->bundle->envelope; $ctx = $env->header->context; $a = $accounts[$ctx->author->account_id]; $cert = $a['devices'][$ctx->author->device_id]['cert'];
        must(array_values(array_filter($members, fn($m) => $m->account_id === $ctx->author->account_id))[0]->role === 'editor');
        must(sodium_crypto_sign_verify_detached(un64($env->signature), fileSigningInputNative($env->header), un64($cert->body->device_signing_key)));
        $digest = b64(hash('sha256', fileDomain('hash', 'file-envelope').fixtureCanonical($env), true)); $observed[$ctx->file_version_id] = $digest;
        verifyGroupFile($step);
    } elseif ($step->kind === 'history') {
        $h = $step->record; $b = $h->body; $d = $b->descriptor; $cert = senderCheck($b->signer, $accounts);
        must(array_values(array_filter($members, fn($m) => $m->account_id === $b->signer->account_id))[0]->role !== 'reader'); groupSignature($h, $cert->body->device_signing_key);
        must(sodium_crypto_sign_verify_detached(un64($b->descriptor_signature), fileDomain('sign', 'history-checkpoint').fixtureCanonical($d), un64($cert->body->device_signing_key)));
        must(fixtureCanonical($b->predecessor) === fixtureCanonical($history) && $d->predecessor_checkpoint_digest === $historyDigest);
        $records = array_merge(...array_map(fn($page) => $page->records, $step->pages)); must(count($records) === count($observed));
        foreach ($records as $record) must(($observed[$record->revision_id] ?? null) === $record->envelope_digest);
        must($d->inventory_digest === inventoryHash('file', 'history-inventory', $step->pages, count($records), fn($page) => b64(hash('sha256', fileDomain('hash', 'history-page').fixtureCanonical($page), true))));
        must(fixtureCanonical($d->closed_rosters) === fixtureCanonical(rosterList($members, $accounts)));
        $historyDigest = b64(hash('sha256', fileDomain('hash', 'history-checkpoint').fixtureCanonical($d), true)); $history = (object) ['version' => $b->sequence, 'digest' => groupHash('history', $h)]; $historyRequired = false; ++$checkpoints;
    }
    $s = $step->expected; must(fixtureCanonical($s->policy) === fixtureCanonical($policy) && fixtureCanonical($s->epoch) === fixtureCanonical($epoch));
    must(fixtureCanonical($s->members) === fixtureCanonical($members) && fixtureCanonical($s->history) === fixtureCanonical($history));
    $changed = $epoch !== null && fixtureCanonical(rosterList($members, $accounts)) !== fixtureCanonical($epochRosters);
    $status = $archived ? 'ARCHIVED' : ($removalRekey || $changed ? 'REKEY_REQUIRED' : (!$historyKnown ? 'UNANCHORED_HISTORY' : ($historyRequired ? 'HISTORY_CLOSURE_REQUIRED' : 'WRITABLE')));
    must($s->write_state === $status);
}
must($epochs === 6 && $grants === 105 && $policies === 8 && $checkpoints === 5);
echo json_encode(['status' => 'PASS', 'scope' => 'PUBLIC_FIXTURE_SUBSET_ONLY', 'checks' => $checks, 'epochs' => $epochs, 'grants_opened' => $grants, 'policies' => $policies, 'checkpoints' => $checkpoints, 'file_bytes' => 50, 'php' => PHP_VERSION, 'sodium' => SODIUM_LIBRARY_VERSION, 'production_auth_SQL_and_general_verifier' => 'NOT_IMPLEMENTED'], JSON_THROW_ON_ERROR)."\n";
function fileSigningInputNative(object $header): string { return fileDomain('sign', 'file-manifest').fixtureCanonical($header); }
function verifyGroupFile(object $step): void {
    $bundle = $step->bundle; $header = $bundle->envelope->header; $context = $header->context; $groupKey = seedBytes(120 + (int) $context->policy->key_epoch * 7);
    $wrap = $bundle->wrap; must(b64(hash('sha256', fileDomain('hash', 'key-wrap').fixtureCanonical($wrap), true)) === $header->key_wrap_digest);
    $manifestKey = openAead(un64($wrap->ciphertext), aad($context, 'file-manifest-key-wrap'), un64($wrap->nonce), $groupKey);
    $manifest = json_decode(openAead(un64($bundle->manifest_ciphertext), aad($context, 'file-manifest', $header->framing), un64($header->manifest_nonce), $manifestKey), false, 32, JSON_THROW_ON_ERROR);
    $input = fileDomain('aad', 'file-chunk').fixtureCanonical((object) ['purpose' => 'file-chunk', 'context' => $context, 'chunk_index' => '0', 'plaintext_chunk_bytes' => $header->framing->plaintext_bytes, 'chunk_count' => '1']);
    $cipher = un64($bundle->chunks[0]); $nonce = un64($manifest->nonce_prefix).str_repeat("\0", 8); $key = un64($manifest->file_data_key);
    must(bin2hex(openAead($cipher, $input, $nonce, $key)) === $step->plaintext_hex);
    $bad = $cipher; $bad[strlen($bad)-1] = chr(ord($bad[strlen($bad)-1]) ^ 1);
    must(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($bad, $input, $nonce, $key) === false);
    must(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $input.'wrong', $nonce, $key) === false);
    sodium_memzero($key); sodium_memzero($manifestKey); sodium_memzero($groupKey);
}
