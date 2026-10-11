<?php

namespace App\Auth;

use App\Crypto\PublicProtocol as P;
use App\Http\ApiException;
use App\Http\ControlJson;
use stdClass;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebAuthn
{
    private SerializerInterface $serializer;

    private CeremonyStepManagerFactory $ceremonies;

    public function __construct()
    {
        $this->serializer = (new WebauthnSerializerFactory(new AttestationStatementSupportManager([new NoneAttestationStatementSupport])))->create();
        $this->ceremonies = new CeremonyStepManagerFactory;
        $this->ceremonies->setAllowedOrigins([(string) config('api.app_origin')], false);
        // Keep the library's null loggers/dispatchers: never attach request/credential logs.
    }

    public function createOptions(string $account, string $handle, array $records = []): string
    {
        $options = new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity('AnyNote', config('passkeys.rp_id')),
            new PublicKeyCredentialUserEntity($handle, P::binary($account), $handle),
            random_bytes(32),
            [new PublicKeyCredentialParameters('public-key', -7), new PublicKeyCredentialParameters('public-key', -257)],
            new AuthenticatorSelectionCriteria(null, 'required', 'required'),
            'none',
            array_map(fn ($r) => $this->record($r)->getPublicKeyCredentialDescriptor(), $records),
            120000,
        );

        return $this->serializer->serialize($options, 'json');
    }

    public function getOptions(): string
    {
        return $this->serializer->serialize(new PublicKeyCredentialRequestOptions(random_bytes(32), config('passkeys.rp_id'), [], 'required', 120000), 'json');
    }

    public function registration(stdClass $credential, string $options): CredentialRecord
    {
        $this->clientData($credential, 'webauthn.create');
        $c = $this->serializer->deserialize(json_encode($credential, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        if (! $c->response instanceof AuthenticatorAttestationResponse || P::b64($c->rawId) !== $credential->id || $credential->rawId !== $credential->id) {
            throw new ApiException('AUTH_REQUIRED');
        }

        return (new AuthenticatorAttestationResponseValidator($this->ceremonies->creationCeremony()))->check($c->response, $this->serializer->deserialize($options, PublicKeyCredentialCreationOptions::class, 'json'), config('passkeys.rp_id'));
    }

    public function assertion(stdClass $credential, string $options, string $record): CredentialRecord
    {
        $this->clientData($credential, 'webauthn.get');
        $c = $this->serializer->deserialize(json_encode($credential, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        $source = $this->record($record);
        if (! $c->response instanceof AuthenticatorAssertionResponse || $c->rawId !== $source->publicKeyCredentialId || P::b64($c->rawId) !== $credential->id || $credential->rawId !== $credential->id) {
            throw new ApiException('AUTH_REQUIRED');
        }

        return (new AuthenticatorAssertionResponseValidator($this->ceremonies->requestCeremony()))->check($source, $c->response, $this->serializer->deserialize($options, PublicKeyCredentialRequestOptions::class, 'json'), config('passkeys.rp_id'), $source->userHandle);
    }

    private function clientData(stdClass $c, string $type): void
    {
        $d = ControlJson::decode(P::binary($c->response->clientDataJSON));
        if (($d->type ?? '') !== $type || ($d->origin ?? '') !== config('api.app_origin') || ($d->crossOrigin ?? false) !== false || isset($d->topOrigin)) {
            throw new ApiException('AUTH_REQUIRED');
        }
    }

    public function serialize(CredentialRecord $record): string
    {
        return $this->serializer->serialize($record, 'json');
    }

    public function record(string $bytes): CredentialRecord
    {
        return $this->serializer->deserialize($bytes, CredentialRecord::class, 'json');
    }
}
