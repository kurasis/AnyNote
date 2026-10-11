<?php

namespace App\Auth\OAuth;

use App\Crypto\PublicProtocol as P;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use stdClass;

/** Per-request repository: every opaque library identifier is scoped to one durable native session. */
final class Repository implements AccessTokenRepositoryInterface, AuthCodeRepositoryInterface, ClientRepositoryInterface, RefreshTokenRepositoryInterface, ScopeRepositoryInterface
{
    public ?string $refreshId = null;

    public function __construct(public stdClass $session, public stdClass $authorization) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return $clientIdentifier === 'anynote-windows' ? new Client($this->authorization->redirect_uri) : null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return $clientIdentifier === 'anynote-windows' && $clientSecret === null && in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return null;
    }

    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        return [];
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        if ($userIdentifier !== $this->session->account_id || $scopes !== []) {
            throw new \LogicException('Invalid native session context');
        }
        $token = new Access;
        $token->setClient($clientEntity);
        $token->setUserIdentifier($userIdentifier);

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $token): void
    {
        $end = new \DateTimeImmutable($this->session->absolute_expires_at, new \DateTimeZone('UTC'));
        $token->setExpiryDateTime(min($token->getExpiryDateTime(), $end));
        DB::table('oauth_access')->where('session_id', $this->session->id)->update(['revoked' => true]);
        DB::table('oauth_access')->insert(['id' => $token->getIdentifier(), 'session_id' => $this->session->id, 'expires_at' => $token->getExpiryDateTime()]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        DB::table('oauth_access')->where('id', $tokenId)->where('session_id', $this->session->id)->update(['revoked' => true]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return ! DB::table('oauth_access')->where('id', $tokenId)->where('session_id', $this->session->id)->where('revoked', false)->where('expires_at', '>', now())->exists();
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new Code;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $code): void
    {
        DB::table('oauth_codes')->insert(['id' => $code->getIdentifier(), 'session_id' => $this->session->id, 'authorization_id' => $this->authorization->id, 'expires_at' => $code->getExpiryDateTime()]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        DB::table('oauth_codes')->where('id', $codeId)->where('session_id', $this->session->id)->update(['revoked' => true]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return ! DB::table('oauth_codes')->where('id', $codeId)->where('session_id', $this->session->id)->where('authorization_id', $this->authorization->id)->where('revoked', false)->where('expires_at', '>', now())->exists();
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new Refresh;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $token): void
    {
        $token->setExpiryDateTime(new \DateTimeImmutable($this->session->absolute_expires_at, new \DateTimeZone('UTC')));
        $this->refreshId = P::b64(random_bytes(16));
        DB::table('refresh_tokens')->insert(['id' => $this->refreshId, 'account_id' => $this->session->account_id, 'device_id' => $this->session->device_id, 'family_id' => $this->session->family_id, 'oauth_identifier' => $token->getIdentifier(), 'secret_hash' => hash('sha256', random_bytes(32)), 'state' => 'active', 'expires_at' => $token->getExpiryDateTime()]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        DB::table('refresh_tokens')->where('oauth_identifier', $tokenId)->where('family_id', $this->session->family_id)->update(['state' => 'used']);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return ! DB::table('refresh_tokens')->where('oauth_identifier', $tokenId)->where('family_id', $this->session->family_id)->where('state', 'active')->where('expires_at', '>', now())->exists();
    }
}
