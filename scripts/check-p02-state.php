<?php
// Independent PUBLIC ASCII fixture subset. Not an input parser, server session,
// group authorization or production roster implementation.
declare(strict_types=1);
ob_start(); require __DIR__.'/check-p02-crypto.php'; ob_end_clean();
$checks = 0;
function stateDomain(string $family, string $purpose): string { return "AnyNote/p02-state-c1/$family/$purpose\0"; }
function stateHash(string $kind, object $record): string { return b64(hash('sha256', stateDomain('hash', $kind).fixtureCanonical($record), true)); }
function stateSignature(object $record, string $key): void {
    $input = stateDomain('sign', $record->body->purpose).fixtureCanonical($record->body);
    must(sodium_crypto_sign_verify_detached(un64($record->signature), $input, un64($key)));
    $bad = un64($record->signature); $bad[0] = chr(ord($bad[0]) ^ 1);
    must(!sodium_crypto_sign_verify_detached($bad, $input, un64($key)));
}
function devicePair(int $index): string {
    $seed = ''; for ($i = 0; $i < 32; ++$i) $seed .= chr(($index * 16 + 11 + $i) % 256);
    return sodium_crypto_box_seed_keypair($seed);
}
function secretProof(object $challenge, object $confirmation, int $index): void {
    $plain = sodium_crypto_box_seal_open(un64($challenge->sealed_challenge), devicePair($index)); must($plain !== false);
    $decoded = json_decode($plain, false, 32, JSON_THROW_ON_ERROR);
    must(stateHash('challenge-plaintext', $decoded) === $challenge->challenge_digest);
    must(fixtureCanonical($decoded->context) === fixtureCanonical($challenge->context));
    must($decoded->secret === $confirmation->body->challenge_response);
    must($confirmation->body->challenge_digest === stateHash('challenge', $challenge));
    stateSignature($confirmation, $challenge->context->device->signing_key);
    sodium_memzero($plain);
}
$f = json_decode(file_get_contents($argv[2]), false, 32, JSON_THROW_ON_ERROR);
must(fixtureCanonical($f->identity) === fixtureCanonical($o->identity));
$head = null; $generation = '0'; $devices = []; $certs = []; $limit = null; $ops = [];
foreach ($f->inputs->events as $index => $event) {
    $b = $event->body; $p = $b->payload;
    must($b->service_id === $f->pin->service_id && $b->account_id === $f->pin->account_id && $b->root_fingerprint === $f->pin->root_fingerprint);
    must(fixtureCanonical($b->predecessor) === fixtureCanonical($head) && $b->version === (string) $index);
    must(!isset($ops[$b->operation_id])); $ops[$b->operation_id] = true;
    $cert = null; $parent = null;
    if ($b->kind === 'register' || $b->kind === 'reset') {
        must(($b->kind === 'register') === ($index === 0));
        must($p->challenge->context->intent === $b->kind && $p->challenge->context->generation === $generation);
        must(fixtureCanonical($p->challenge->context->roster) === fixtureCanonical($head));
        $next = $b->kind === 'reset' ? (string) ((int) $generation + 1) : '0'; must($b->generation === $next);
        must($limit === null || $limit === $p->active_device_limit); $limit = $p->active_device_limit;
        must((int) $limit >= 1 && (int) $limit <= 32);
        stateSignature($event, $f->identity->body->root_signing_key);
        secretProof($p->challenge, $p->confirmation, $b->kind === 'register' ? 0 : 3);
        $cert = $p->certificate; $issuerKey = $f->identity->body->root_signing_key;
        must($cert->body->pairing_transcript_digest === stateHash('challenge', $p->challenge));
        if ($b->kind === 'reset') foreach ($devices as $device) $device->status = 'REVOKED';
        $generation = $next;
    } elseif ($b->kind === 'enroll') {
        must($b->generation === $generation);
        $t = $p->transcript; $offer = $t->offer; $response = $t->response; $approval = $p->approval; $confirmation = $p->confirmation;
        $parent = $response->body->approver->device_id; must($devices[$parent]->status === 'ACTIVE');
        $issuerKey = $certs[$parent]->body->device_signing_key;
        stateSignature($offer, $offer->body->device->signing_key); stateSignature($response, $issuerKey);
        stateSignature($approval, $issuerKey); stateSignature($confirmation, $offer->body->device->signing_key); stateSignature($event, $offer->body->device->signing_key);
        must($response->body->offer_digest === stateHash('offer', $offer));
        must($approval->body->transcript_digest === stateHash('transcript', $t));
        must($confirmation->body->approval_digest === stateHash('approval', $approval));
        must($confirmation->body->session_binding === $offer->body->session_binding);
        foreach ([$offer->body, $response->body, $approval->body, $confirmation->body] as $body) {
            must(fixtureCanonical($body->roster) === fixtureCanonical($head) && $body->generation === $generation);
            must($body->operation_id === $b->operation_id);
        }
        if ($t->invitation !== null) { stateSignature($t->invitation, $issuerKey); must(stateHash('invitation', $t->invitation) === $offer->body->invitation_digest); }
        $plain = sodium_crypto_box_seal_open(un64($approval->body->sealed_challenge), devicePair($index)); must($plain !== false);
        $proof = json_decode($plain, false, 32, JSON_THROW_ON_ERROR);
        must(stateHash('pairing-proof-plaintext', $proof) === $approval->body->challenge_digest && $proof->secret === $confirmation->body->challenge_response);
        sodium_memzero($plain); $cert = $approval->body->certificate;
        must($confirmation->body->certificate_digest === b64(hash('sha256', domain('hash', 'device-certificate').fixtureCanonical($cert), true)));
    } else {
        must($b->kind === 'revoke' && $b->generation === $generation && $devices[$b->signer]->status === 'ACTIVE');
        stateSignature($event, $certs[$b->signer]->body->device_signing_key);
        $closure = array_fill_keys($p->targets, true);
        do { $before = count($closure); foreach ($devices as $id => $device) if ($device->status === 'ACTIVE' && isset($closure[$device->parent_device_id ?? ''])) $closure[$id] = true; } while (count($closure) !== $before);
        $ids = array_keys($closure); sort($ids, SORT_STRING); must($ids === $p->affected_devices && !isset($closure[$b->signer]));
        foreach ($ids as $id) $devices[$id]->status = 'REVOKED';
    }
    if ($cert !== null) {
        $input = signInput('provisional-device-certificate', $cert->body);
        must(sodium_crypto_sign_verify_detached(un64($cert->signature), $input, un64($issuerKey)));
        must($cert->body->recovery_generation === $generation && fixtureCanonical($cert->body->predecessor_roster) === fixtureCanonical($head));
        $id = $cert->body->device_id; must(!isset($devices[$id])); $certs[$id] = $cert;
        $devices[$id] = (object) ['device_id' => $id, 'status' => 'ACTIVE', 'generation' => $generation, 'parent_device_id' => $parent,
            'certificate_digest' => b64(hash('sha256', domain('hash', 'device-certificate').fixtureCanonical($cert), true))];
        must(count(array_filter($devices, fn($d) => $d->status === 'ACTIVE')) <= (int) $limit);
    }
    $head = (object) ['version' => $b->version, 'digest' => stateHash('event', $event)];
    $snapshot = $f->outputs->snapshots[$index];
    must($head->digest === $f->outputs->event_digests[$index]);
    must(fixtureCanonical($head) === fixtureCanonical($snapshot->head) && $generation === $snapshot->generation);
    must(fixtureCanonical(array_values($devices)) === fixtureCanonical($snapshot->devices));
}
must(fixtureCanonical($head) === fixtureCanonical($f->outputs->final_head));
$frames = 0;
foreach ($f->inputs->pairing_channels as $channel) foreach ($channel->frames as $frameInput) {
    $frame = $frameInput->frame; $key = un64($channel->qr->channel_key);
    $aad = stateDomain('aad', 'pairing-channel-frame').fixtureCanonical($frame->context);
    $stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull(un64($frame->header), $key);
    $opened = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, un64($frame->ciphertext), $aad);
    must($opened !== false && $opened[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
    must($opened[0] === fixtureCanonical($frameInput->expected));
    $bad = un64($frame->ciphertext); $bad[strlen($bad)-1] = chr(ord($bad[strlen($bad)-1]) ^ 1);
    foreach ([[$bad, $aad, $key], [un64($frame->ciphertext), $aad.'wrong', $key], [un64($frame->ciphertext), $aad, str_repeat("\0", 32)]] as [$cipher, $auth, $secret]) {
        $stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull(un64($frame->header), $secret);
        must(sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $cipher, $auth) === false);
    }
    ++$frames;
}
echo json_encode(['status' => 'PASS', 'scope' => 'PUBLIC_FIXTURE_SUBSET_ONLY', 'checks' => $checks, 'events' => count($f->inputs->events),
    'channel_frames' => $frames, 'php' => PHP_VERSION, 'sodium' => SODIUM_LIBRARY_VERSION,
    'production_parser_sessions_and_group_authorization' => 'NOT_EVALUATED'], JSON_THROW_ON_ERROR)."\n";
