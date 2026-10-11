<?php

namespace App\Crypto;

use App\Http\ApiException;
use App\Http\ControlJson;
use Opis\JsonSchema\Validator;
use stdClass;
use Truschery\Kanon\Json;

/** Closed public frames only. General encrypted-payload JCS belongs to clients. */
final class PublicProtocol
{
    private Validator $validator;

    public function __construct()
    {
        $this->validator = new Validator;
        foreach (json_decode(file_get_contents(app_path('Generated/schemas.json')), false, 512, JSON_THROW_ON_ERROR) as $schema) {
            $this->validator->resolver()->registerRaw($schema);
        }
        $formats = $this->validator->parser()->getFormatResolver();
        foreach ([12, 16, 24, 32, 48, 64] as $size) {
            $formats->registerCallable('string', 'base64url-'.$size, fn ($s) => self::isBinary($s, $size));
        }
        $formats->registerCallable('string', 'base64url-variable', fn ($s) => self::isBinary($s));
        $formats->registerCallable('string', 'base64url-sealed', fn ($s) => self::isBinary($s) && strlen(self::binary($s)) >= 48 && strlen(self::binary($s)) <= 4096);
        foreach (['u63' => '9223372036854775807', '119' => '119', '120' => '120', '199' => '199', '200' => '200', '65536' => '65536', '100000' => '100000', '8388608' => '8388608', '8388624' => '8388624', '1000000000' => '1000000000', '9223372036854775807' => '9223372036854775807'] as $suffix => $max) {
            $formats->registerCallable('string', 'decimal-'.$suffix, fn ($s) => self::counter($s, $max));
        }
    }

    public static function counter(string $s, string $max = '9223372036854775807'): bool
    {
        return preg_match('/^(0|[1-9][0-9]*)$/D', $s) === 1 && (strlen($s) < strlen($max) || (strlen($s) === strlen($max) && strcmp($s, $max) <= 0));
    }

    public static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function isBinary(string $s, ?int $length = null): bool
    {
        $b = base64_decode(strtr($s, '-_', '+/'), true);

        return $b !== false && ($length === null || strlen($b) === $length) && self::b64($b) === $s;
    }

    public static function binary(string $s): string
    {
        if (! self::isBinary($s)) {
            throw new ApiException('MALFORMED_ENVELOPE');
        }

        return base64_decode(strtr($s, '-_', '+/'), true);
    }

    public function decode(string $component, string $kind, string $bytes): stdClass
    {
        $allowed = ['p02-v1' => ['bundle', 'context', 'header', 'wrap', 'envelope', 'receipt', 'export-footer-body'], 'p02-identity-c1' => ['identity', 'certificate', 'identity-body', 'certificate-body', 'grant-body', 'grant'], 'p02-file-c1' => ['header', 'envelope', 'checkpoint'], 'p02-state-c1' => ['invitation-body', 'offer-body', 'response-body', 'approval-body', 'confirmation-body', 'possession-body', 'event-body'], 'p02-group-c2' => ['invitation-body', 'acceptance-body', 'policy-body', 'epoch-intent-body', 'descriptor-body', 'epoch-commit-body', 'history-body'], 'p04-api' => ['readiness', 'object-commit', 'commit-result', 'quota-request', 'quota-result', 'invite-request', 'invite-result']];
        if (! in_array($kind, $allowed[$component] ?? [], true)) {
            throw new ApiException('UNSUPPORTED_SCHEMA');
        }
        $cap = $kind === 'bundle' || $kind === 'object-commit' ? 4194304 : 65536;
        if (strlen($bytes) > $cap) {
            throw new ApiException('REQUEST_TOO_LARGE');
        }
        $value = ControlJson::decode($bytes);
        $id = ['p02-v1' => 'urn:anynote:p02:complete-contract:v1', 'p02-identity-c1' => 'urn:anynote:p02:identity-contract:c1', 'p02-file-c1' => 'urn:anynote:p02:file-contract:c1', 'p02-state-c1' => 'urn:anynote:p02:state-contract:c1', 'p02-group-c2' => 'urn:anynote:p02:group-contract:c2', 'p04-api' => 'urn:anynote:p04:api'][$component];
        if (! $this->validator->validate($value, $id.'#/$defs/'.$kind)->isValid()) {
            throw new ApiException('MALFORMED_ENVELOPE');
        }

        return $value;
    }

    public static function canonical(stdClass $publicFrame): string
    {
        // Only validated closed public DTOs reach this adapter. Their keys are ASCII,
        // numeric values are schema-bounded small integers. Secret payloads are
        // never admitted here; general floating-point JCS is implemented by clients.
        return Json::canonicalize($publicFrame);
    }

    public static function digest(string $component, string $kind, stdClass $frame): string
    {
        return self::b64(hash('sha256', 'AnyNote/'.$component.'/hash/'.$kind."\0".self::canonical($frame), true));
    }

    public static function verify(string $component, string $purpose, stdClass $body, string $signature, string $publicKey): void
    {
        if (! self::isBinary($signature, 64) || ! self::isBinary($publicKey, 32) || ! sodium_crypto_sign_verify_detached(self::binary($signature), 'AnyNote/'.$component.'/sign/'.$purpose."\0".self::canonical($body), self::binary($publicKey))) {
            throw new ApiException('INVALID_SIGNATURE');
        }
    }

    /** Signature validity alone establishes no role, current policy or trusted key. */
    public function signedFrame(string $component, string $kind, string $bytes, string $signature, string $pinnedPublicKey): stdClass
    {
        $purposes = ['p02-identity-c1' => ['identity-body' => 'account-root-identity', 'certificate-body' => 'provisional-device-certificate', 'grant-body' => 'group-key-distribution'], 'p02-file-c1' => ['header' => 'file-manifest', 'checkpoint' => 'history-checkpoint'], 'p02-v1' => ['header' => 'object-revision', 'export-footer-body' => 'export-footer'], 'p02-state-c1' => array_fill_keys(['invitation-body', 'offer-body', 'response-body', 'approval-body', 'confirmation-body', 'possession-body', 'event-body'], null), 'p02-group-c2' => array_fill_keys(['invitation-body', 'acceptance-body', 'policy-body', 'epoch-intent-body', 'descriptor-body', 'epoch-commit-body', 'history-body'], null)];
        if (! array_key_exists($kind, $purposes[$component] ?? [])) {
            throw new ApiException('UNSUPPORTED_SCHEMA');
        }
        $body = $this->decode($component, $kind, $bytes);
        $purpose = $purposes[$component][$kind] ?? $body->purpose;
        self::verify($component, $purpose, $body, $signature, $pinnedPublicKey);

        return $body;
    }

    public function bundle(string $bytes, string $publicKey): stdClass
    {
        $b = $this->decode('p02-v1', 'bundle', $bytes);
        $h = $b->envelope->header;
        $c = $h->context;
        if (self::canonical($c) !== self::canonical($b->wrap->context)) {
            throw new ApiException('MALFORMED_ENVELOPE');
        }
        self::verify('p02-v1', 'object-revision', $h, $b->envelope->signature, $publicKey);
        $ciphertext = self::binary($b->ciphertext);
        if (strlen($ciphertext) < 16 || strlen($ciphertext) > 2097168 || (string) strlen($ciphertext) !== $h->ciphertext_bytes || self::b64(hash('sha256', $ciphertext, true)) !== $h->ciphertext_digest || self::digest('p02-v1', 'wrap', $b->wrap) !== $h->key_wrap_digest) {
            throw new ApiException('MALFORMED_ENVELOPE');
        }
        foreach ([$c->parents, $c->attachments] as $index => $items) {
            $last = null;
            foreach ($items as $item) {
                $key = $index === 0 ? $item->revision_id : $item->file_id.'/'.$item->file_version_id;
                if (($last !== null && strcmp($last, $key) >= 0) || ($index === 0 && $key === $c->revision_id)) {
                    throw new ApiException('MALFORMED_ENVELOPE');
                }
                $last = $key;
            }
        }
        if (($c->object_kind === 'entry') !== ($c->thread_id !== null) || ($c->object_kind !== 'entry' && $c->attachments !== []) || (($c->action === 'create') !== ($c->parents === []))) {
            throw new ApiException('MALFORMED_ENVELOPE');
        }

        return $b;
    }
}
