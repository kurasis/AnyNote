<?php

namespace App\Auth;

use App\Auth\OAuth\Repository;
use App\Auth\OAuth\User;
use App\Backend\Authorization;
use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use stdClass;

final class Native
{
    public function __construct(private Sessions $sessions) {}

    private function server(Repository $repo): AuthorizationServer
    {
        $server = new AuthorizationServer($repo, $repo, $repo, config('passkeys.private_key'), hash_hmac('sha256', "AnyNote/P06/oauth-encryption\0", (string) config('app.key')));
        $code = new AuthCodeGrant($repo, $repo, new \DateInterval('PT60S'));
        $code->setRefreshTokenTTL(new \DateInterval('P30D'));
        $refresh = new RefreshTokenGrant($repo);
        $refresh->setRefreshTokenTTL(new \DateInterval('P30D'));
        $server->enableGrantType($code, new \DateInterval('PT15M'));
        $server->enableGrantType($refresh, new \DateInterval('PT15M'));

        return $server;
    }

    public function authorize(stdClass $body): array
    {
        if (DB::table('native_authorizations')->count() >= 50000) {
            throw new ApiException('RESOURCE_LIMIT');
        }
        Policy::redirect($body->redirect_uri);
        $id = P::b64(random_bytes(16));
        DB::table('native_authorizations')->insert(['id' => $id, 'binding_hash' => hash('sha256', random_bytes(32)), 'expires_at' => now()->addMinutes(5), 'data' => json_encode($body, JSON_THROW_ON_ERROR)]);

        return ['version' => 1, 'authorization_id' => $id, 'consent_url' => config('api.app_origin').'/auth/?authorization='.$id];
    }

    public function consent(Request $r, string $id): array
    {
        $this->sessions->current($r);

        return DB::transaction(function () use ($r, $id) {
            $a = DB::table('native_authorizations')->where('id', $id)->lockForUpdate()->first();
            if (! $a || $a->expires_at <= now()->format('Y-m-d H:i:s') || $a->consumed_at !== null) {
                throw new ApiException('NOT_FOUND');
            }
            $d = json_decode($a->data);
            $binding = Sessions::binding($r);
            if (isset($d->consent_binding) && $d->consent_binding !== $binding) {
                throw new ApiException('NOT_FOUND');
            }
            $d->consent_binding = $binding;
            DB::table('native_authorizations')->where('id', $id)->update(['data' => json_encode($d, JSON_THROW_ON_ERROR)]);

            return ['version' => 1, 'authorization_id' => $id, 'redirect_uri' => $d->redirect_uri, 'device_commitment' => $d->device_commitment];
        }, 3);
    }

    public function approve(Request $r, string $id): array
    {
        return DB::transaction(function () use ($r, $id) {
            $browser = $this->sessions->current($r, true);
            Sessions::recent($browser);
            $a = DB::table('native_authorizations')->where('id', $id)->lockForUpdate()->first();
            if (! $a || $a->expires_at <= now()->format('Y-m-d H:i:s') || $a->consumed_at !== null) {
                throw new ApiException('NOT_FOUND');
            }
            $d = json_decode($a->data);
            if (($d->consent_binding ?? null) !== Sessions::binding($r)) {
                throw new ApiException('AUTH_REQUIRED');
            }
            if (Sessions::live($browser->account_id)->count() >= 100) {
                throw new ApiException('RESOURCE_LIMIT');
            }
            $session = P::b64(random_bytes(16));
            DB::table('auth_sessions')->insert(['id' => $session, 'account_id' => $browser->account_id, 'device_id' => null, 'secret_hash' => hash('sha256', random_bytes(32)), 'recovery_generation' => $browser->recovery_generation, 'state' => 'restricted', 'transport' => 'native', 'family_id' => P::b64(random_bytes(16)), 'device_commitment' => $d->device_commitment, 'expires_at' => now()->addSeconds(60), 'absolute_expires_at' => now()->addDays(30), 'created_at' => now(), 'authenticated_at' => now()]);
            $d->session_id = $session;
            $d->id = $id;
            $d->issuer = config('passkeys.issuer');
            $repo = new Repository(DB::table('auth_sessions')->where('id', $session)->first(), $d);
            $server = $this->server($repo);
            $params = ['response_type' => 'code', 'client_id' => $d->client_id, 'redirect_uri' => $d->redirect_uri, 'state' => $d->state, 'code_challenge' => $d->code_challenge, 'code_challenge_method' => 'S256'];
            $psr = (new ServerRequest('GET', config('passkeys.issuer').'/api/v1/auth/native/authorize'))->withQueryParams($params);
            $auth = $server->validateAuthorizationRequest($psr);
            $auth->setUser(new User($browser->account_id));
            $auth->setAuthorizationApproved(true);
            $response = $server->completeAuthorizationRequest($auth, new Response);
            $url = $response->getHeaderLine('Location').'&iss='.rawurlencode(config('passkeys.issuer'));
            DB::table('native_authorizations')->where('id', $id)->update(['account_id' => $browser->account_id, 'consumed_at' => now(), 'expires_at' => $repo->session->absolute_expires_at, 'data' => json_encode($d, JSON_THROW_ON_ERROR)]);

            return ['version' => 1, 'redirect_uri' => $url];
        }, 3);
    }

    public function token(stdClass $body): array
    {
        if ($body->issuer !== config('passkeys.issuer')) {
            throw new ApiException('AUTH_REQUIRED');
        }
        $result = DB::transaction(function () use ($body) {
            if ($body->grant_type === 'authorization_code') {
                $a = DB::table('native_authorizations')->where('id', $body->authorization_id)->first();
                $d = $a ? json_decode($a->data) : null;
                if (! isset($d->session_id) || $body->redirect_uri !== $d->redirect_uri || $d->issuer !== $body->issuer) {
                    return new ApiException('AUTH_REQUIRED');
                }
                $candidate = DB::table('auth_sessions')->where('id', $d->session_id)->first();
            } else {
                $refresh = DB::table('refresh_tokens')->where('secret_hash', hash('sha256', $body->refresh_token))->first();
                $candidate = $refresh ? DB::table('auth_sessions')->where('family_id', $refresh->family_id)->first() : null;
                $a = $candidate ? DB::table('native_authorizations')->where('account_id', $candidate->account_id)->whereRaw("JSON_UNQUOTE(JSON_EXTRACT(data, '$.session_id')) = ?", [$candidate->id])->first() : null;
                $d = $a ? json_decode($a->data) : null;
            }
            if (! $candidate || ! $d) {
                return new ApiException('AUTH_REQUIRED');
            }
            $u = DB::table('users')->where('id', $candidate->account_id)->lockForUpdate()->first();
            $s = DB::table('auth_sessions')->where('id', $candidate->id)->lockForUpdate()->first();
            if (! $u || $u->status !== 'active' || $s->state === 'revoked' || $s->absolute_expires_at <= now()->format('Y-m-d H:i:s')) {
                return new ApiException('AUTH_REQUIRED');
            }
            if ($body->grant_type === 'refresh_token') {
                $refresh = DB::table('refresh_tokens')->where('id', $refresh->id)->lockForUpdate()->first();
                if ($refresh->state !== 'active') {
                    Sessions::revoke($s->id); // COMMIT family revocation even though the grant is denied.

                    return new ApiException('AUTH_REQUIRED');
                }
                if ($refresh->expires_at <= now()->format('Y-m-d H:i:s')) {
                    return new ApiException('AUTH_REQUIRED');
                }
            }
            // A rotation may preserve a proven device only while its current certificate/generation remains valid.
            if ($s->state === 'trusted') {
                try {
                    [$identity, $device, $cert] = app(Authorization::class)->certifiedDevice($s->account_id, $s->device_id);
                    if ($s->recovery_generation !== $identity->recovery_generation || $s->device_commitment !== Proof::commitment(Proof::device($cert))) {
                        throw new ApiException('AUTH_REQUIRED');
                    }
                } catch (\Throwable) {
                    Sessions::revoke($s->id);

                    return new ApiException('AUTH_REQUIRED');
                }
            }
            try {
                return DB::transaction(function () use ($body, $s, $d) {
                    $repo = new Repository($s, $d);
                    $psr = (new ServerRequest('POST', config('passkeys.issuer').'/api/v1/auth/native/token'))->withParsedBody((array) $body);
                    $response = $this->server($repo)->respondToAccessTokenRequest($psr, new Response);
                    $tokens = json_decode((string) $response->getBody(), true, 32, JSON_THROW_ON_ERROR);
                    if (! isset($tokens['access_token'], $tokens['refresh_token']) || $repo->refreshId === null) {
                        throw new \LogicException('Missing OAuth grant output');
                    }
                    DB::table('refresh_tokens')->where('id', $repo->refreshId)->update(['secret_hash' => hash('sha256', $tokens['refresh_token'])]);
                    DB::table('auth_sessions')->where('id', $s->id)->update(['secret_hash' => hash('sha256', $tokens['access_token']), 'expires_at' => min(now()->addMinutes(15)->format('Y-m-d H:i:s'), $s->absolute_expires_at), 'last_seen_at' => now()]);

                    return ['version' => 1, ...$tokens, 'issuer' => config('passkeys.issuer'), 'session' => Sessions::public($s)];
                });
            } catch (\Throwable) {
                return new ApiException('AUTH_REQUIRED');
            }
        }, 3);
        if ($result instanceof ApiException) {
            throw $result;
        }

        return $result;
    }
}
