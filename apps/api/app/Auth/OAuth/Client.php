<?php

namespace App\Auth\OAuth;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

final class Client implements ClientEntityInterface
{
    use ClientTrait, EntityTrait;

    public function __construct(string $redirect)
    {
        $this->identifier = 'anynote-windows';
        $this->name = 'AnyNote Windows';
        $this->redirectUri = $redirect;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }
}
