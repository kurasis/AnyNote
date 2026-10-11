<?php

namespace App\Backend;

final readonly class Actor
{
    public function __construct(public string $accountId, public string $deviceId, public string $sessionId, public string $rootFingerprint, public string $generation, public string $rosterSequence, public string $rosterDigest, public string $signingKey, public bool $contentSigner, public bool $admin, public bool $recent) {}
}
