<?php
// Public fixture-only independent reference. This is NOT a general RFC 8785
// parser/schema/authorization API. Fixed ASCII property names, integer 1 and
// string values are sufficient for this reviewed fixture subset only.
declare(strict_types=1);
$checks = 0;
function must(bool $condition): void { global $checks; ++$checks; if (!$condition) throw new RuntimeException('PUBLIC_FIXTURE_MISMATCH'); }
function b64(string $bytes): string { return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='); }
function un64(string $text): string {
    $bytes = base64_decode(strtr($text, '-_', '+/'), true);
    must($bytes !== false && b64($bytes) === $text);
    return $bytes;
}
function fixtureCanonical(mixed $value): string {
    if (is_object($value)) {
        $props = get_object_vars($value);
        foreach (array_keys($props) as $key) must(preg_match('/^[\x20-\x7e]+$/D', $key) === 1);
        ksort($props, SORT_STRING);
        $items = [];
        foreach ($props as $key => $item) $items[] = json_encode($key, JSON_THROW_ON_ERROR).':'.fixtureCanonical($item);
        return '{'.implode(',', $items).'}';
    }
    if (is_array($value)) return '['.implode(',', array_map('fixtureCanonical', $value)).']';
    must(!is_float($value));
    return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
function domain(string $family, string $purpose): string { return "AnyNote/p02-identity-c1/$family/$purpose\0"; }
function fileDomain(string $family, string $purpose): string { return "AnyNote/p02-file-c1/$family/$purpose\0"; }
function signInput(string $purpose, object $body): string { return domain('sign', $purpose).fixtureCanonical($body); }
function aad(object $context, string $purpose, ?object $framing = null): string {
    $value = (object) ['purpose' => $purpose, 'context' => $context];
    if ($framing !== null) $value->framing = $framing;
    return fileDomain('aad', $purpose).fixtureCanonical($value);
}
function openAead(string $ciphertext, string $aad, string $nonce, string $key): string {
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
    must($plain !== false);
    return $plain;
}
$fixture = json_decode(file_get_contents($argv[1]), false, 32, JSON_THROW_ON_ERROR);
$o = $fixture->outputs;
$secret = hex2bin($fixture->input->root_secret_hex);
$context = fixtureCanonical($fixture->input->context);
$salt = hash('sha256', domain('hkdf', 'extract-salt').$context, true);
$rootSeeds = [];
foreach ($o->hkdf as $vector) {
    $info = domain('hkdf', $vector->purpose).$context;
    $seed = hash_hkdf('sha256', $secret, 32, $info, $salt);
    must(bin2hex($salt) === $vector->salt_hex && bin2hex($info) === $vector->info_hex && bin2hex($seed) === $vector->seed_hex);
    $rootSeeds[] = $seed;
}
$rootSigning = sodium_crypto_sign_seed_keypair($rootSeeds[0]);
$recovery = sodium_crypto_box_seed_keypair($rootSeeds[1]);
must(b64(sodium_crypto_sign_publickey($rootSigning)) === $o->identity->body->root_signing_key);
must(b64(sodium_crypto_box_publickey($recovery)) === $o->identity->body->recovery_encryption_key);
$identityInput = signInput('account-root-identity', $o->identity->body);
must(bin2hex($identityInput) === $o->identity_signing_input_hex);
must(bin2hex(fixtureCanonical($o->identity)) === $o->identity_canonical_hex);
must(b64(hash('sha256', domain('hash', 'account-root-identity').fixtureCanonical($o->identity->body), true)) === $o->pin->root_fingerprint);
must(sodium_crypto_sign_verify_detached(un64($o->identity->signature), $identityInput, sodium_crypto_sign_publickey($rootSigning)));
must(b64(sodium_crypto_sign_detached($identityInput, sodium_crypto_sign_secretkey($rootSigning))) === $o->identity->signature);
$bad = un64($o->identity->signature); $bad[0] = chr(ord($bad[0]) ^ 1);
must(!sodium_crypto_sign_verify_detached($bad, $identityInput, sodium_crypto_sign_publickey($rootSigning)));
foreach ($o->certificates as $vector) {
    $input = signInput('provisional-device-certificate', $vector->record->body);
    must(bin2hex($input) === $vector->signing_input_hex);
    must(sodium_crypto_sign_verify_detached(un64($vector->record->signature), $input, sodium_crypto_sign_publickey($rootSigning)));
    must(b64(sodium_crypto_sign_detached($input, sodium_crypto_sign_secretkey($rootSigning))) === $vector->record->signature);
    must(b64(hash('sha256', domain('hash', 'device-certificate').fixtureCanonical($vector->record), true)) === $vector->digest);
}
$receiver = sodium_crypto_box_seed_keypair(hex2bin($fixture->input->receiver_encryption_seed_hex));
$senderPublic = un64($o->certificates[0]->record->body->device_signing_key);
$recipientPairs = [$receiver, $recovery];
foreach ($fixture->sealed_inputs as $i => $record) {
    must(fixtureCanonical($record->body->context) === fixtureCanonical($o->grant_contexts[$i]));
    $input = signInput('group-key-distribution', $record->body);
    must(sodium_crypto_sign_verify_detached(un64($record->signature), $input, $senderPublic));
    $bad = un64($record->signature); $bad[0] = chr(ord($bad[0]) ^ 1);
    must(!sodium_crypto_sign_verify_detached($bad, $input, $senderPublic));
    $plain = sodium_crypto_box_seal_open(un64($record->body->sealed_ciphertext), $recipientPairs[$i]);
    must($plain !== false);
    $inner = json_decode($plain, false, 32, JSON_THROW_ON_ERROR);
    must($inner->purpose === 'group-key-plaintext' && fixtureCanonical($inner->context) === fixtureCanonical($record->body->context));
    $groupKey = un64($inner->group_key);
    $file = $o->file; $header = $file->envelope->header;
    must(fixtureCanonical($header->context) === fixtureCanonical($o->file_context));
    must(sodium_crypto_sign_verify_detached(un64($file->envelope->signature), fileDomain('sign', 'file-manifest').fixtureCanonical($header), $senderPublic));
    must(b64(hash('sha256', fileDomain('hash', 'key-wrap').fixtureCanonical($file->wrap), true)) === $header->key_wrap_digest);
    $manifestKey = openAead(un64($file->wrap->ciphertext), aad($header->context, 'file-manifest-key-wrap'), un64($file->wrap->nonce), $groupKey);
    $manifestCipher = un64($file->manifest_ciphertext);
    must(strlen($manifestCipher) === (int) $header->manifest_ciphertext_bytes && b64(hash('sha256', $manifestCipher, true)) === $header->manifest_ciphertext_digest);
    $manifestBytes = openAead($manifestCipher, aad($header->context, 'file-manifest', $header->framing), un64($header->manifest_nonce), $manifestKey);
    $manifest = json_decode($manifestBytes, false, 32, JSON_THROW_ON_ERROR);
    must($manifest->purpose === 'file-manifest-plaintext');
    must(fixtureCanonical($manifest->context) === fixtureCanonical($header->context) && fixtureCanonical($manifest->framing) === fixtureCanonical($header->framing));
    $chunk = un64($file->chunks[0]); $part = $header->framing->parts[0];
    must(strlen($chunk) === (int) $part->ciphertext_bytes && b64(hash('sha256', $chunk, true)) === $part->ciphertext_digest);
    $chunkAad = fileDomain('aad', 'file-chunk').fixtureCanonical((object) ['purpose' => 'file-chunk', 'context' => $header->context,
        'chunk_index' => '0', 'plaintext_chunk_bytes' => $header->framing->plaintext_bytes, 'chunk_count' => '1']);
    $nonce = un64($manifest->nonce_prefix).str_repeat("\0", 8);
    $fileKey = un64($manifest->file_data_key);
    $output = openAead($chunk, $chunkAad, $nonce, $fileKey);
    must(bin2hex($output) === $o->plaintext_hex && b64(hash('sha256', $output, true)) === $o->plaintext_sha256 && $manifest->plaintext_digest === $o->plaintext_sha256);
    $bad = $chunk; $bad[strlen($bad)-1] = chr(ord($bad[strlen($bad)-1]) ^ 1);
    must(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($bad, $chunkAad, $nonce, $fileKey) === false);
    must(sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($chunk, $chunkAad."wrong", $nonce, $fileKey) === false);
    sodium_memzero($groupKey); sodium_memzero($manifestKey); sodium_memzero($fileKey); sodium_memzero($plain); sodium_memzero($manifestBytes); sodium_memzero($output);
}
echo json_encode(['status' => 'PASS', 'scope' => 'PUBLIC_FIXTURE_SUBSET_ONLY', 'checks' => $checks,
    'php' => PHP_VERSION, 'sodium' => SODIUM_LIBRARY_VERSION, 'fresh_recipient_paths' => ['device', 'account-recovery'],
    'plaintext_bytes' => strlen(hex2bin($o->plaintext_hex)), 'production_parser_and_authorization' => 'NOT_EVALUATED'], JSON_THROW_ON_ERROR)."\n";
