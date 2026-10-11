<?php

namespace App\Auth\OAuth;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

final class Refresh implements RefreshTokenEntityInterface
{
    use EntityTrait, RefreshTokenTrait;
}
