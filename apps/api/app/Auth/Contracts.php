<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use App\Http\ControlJson;
use Opis\JsonSchema\Validator;
use stdClass;

/** Authentication DTOs are separate from the public-content-signature verifier. */
final class Contracts
{
    private Validator $validator;

    public function __construct()
    {
        $this->validator = new Validator;
        foreach (json_decode(file_get_contents(app_path('Generated/schemas.json')), false, 512, JSON_THROW_ON_ERROR) as $schema) {
            $this->validator->resolver()->registerRaw($schema);
        }
        $f = $this->validator->parser()->getFormatResolver();
        foreach ([12, 16, 24, 32, 48, 64] as $n) {
            $f->registerCallable('string', 'base64url-'.$n, fn ($s) => P::isBinary($s, $n));
        }
        $f->registerCallable('string', 'base64url-variable', fn ($s) => P::isBinary($s));
        $f->registerCallable('string', 'base64url-sealed', fn ($s) => P::isBinary($s) && strlen(P::binary($s)) >= 48 && strlen(P::binary($s)) <= 4096);
        $f->registerCallable('string', 'bounded-binary-4096', fn ($s) => P::isBinary($s) && strlen(P::binary($s)) >= 48 && strlen(P::binary($s)) <= 4096);
        $f->registerCallable('string', 'bounded-binary-16384', fn ($s) => P::isBinary($s) && strlen(P::binary($s)) >= 18 && strlen(P::binary($s)) <= 16384);
        $f->registerCallable('string', 'decimal-u63', fn ($s) => P::counter($s));
    }

    public function value(string $component, string $kind, stdClass $value): stdClass
    {
        $ids = ['p06' => 'urn:anynote:p06:auth:v1', 'p08' => 'urn:anynote:p08:devices:v1', 'p09' => 'urn:anynote:p09:notes:v1', 'p10' => 'urn:anynote:p10:shared:v1', 'group' => 'urn:anynote:p02:group-contract:c2', 'state' => 'urn:anynote:p02:state-contract:c1', 'identity' => 'urn:anynote:p02:identity-contract:c1'];
        if (! isset($ids[$component]) || ! preg_match('/^[a-z-]+$/D', $kind) || ! $this->validator->validate($value, $ids[$component].'#/$defs/'.$kind)->isValid()) {
            throw new ApiException('INVALID_REQUEST');
        }

        return $value;
    }

    public function decode(string $kind, string $bytes): stdClass
    {
        if (strlen($bytes) > 262144) {
            throw new ApiException('REQUEST_TOO_LARGE');
        }

        return $this->value('p06', $kind, ControlJson::decode($bytes));
    }
}
