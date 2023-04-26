<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Exception;
use Illuminate\Support\Facades\Config;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\JwtToken;
use KeycloakAuthGuard\Services\RealmJwkRetrieverInterface;
use stdClass;

readonly class JwtTokenDecoder
{
    private string $keycloakBaseUrl;

    private string $realm;

    public function __construct(private RealmJwkRetrieverInterface $jwkRetriever)
    {
        $this->keycloakBaseUrl = trim(Config::get('keycloak.base_url'), '/');
        $this->realm = Config::get('keycloak.realm');
    }

    /**
     * @throws InvalidJwtTokenException
     */
    public function decode(string $token): ?stdClass
    {
        try {
            $token = JwtToken::decode(
                $token,
                $this->jwkRetriever->getJwkOrJwks(),
                Config::get('keycloak.leeway')
            );
        } catch (Exception $e) {
            throw new InvalidJwtTokenException('JWT token is invalid', 0, $e);
        }

        if (empty($token)) {
            return null;
        }

        $this->validate($token);

        return $token;
    }

    /**
     * @throws InvalidJwtTokenException
     */
    private function validate(stdClass $token): void
    {
        if (! empty(Config::get('keycloak.accepted_authorized_parties', ''))) {
            $acceptedAuthorizedParties = explode(',', Config::get('keycloak.accepted_authorized_parties'));
            if (! property_exists($token, 'azp')) {
                throw new InvalidJwtTokenException("Token 'azp' is not defined");
            }

            if (! in_array($token->azp, $acceptedAuthorizedParties)) {
                throw new InvalidJwtTokenException("Token 'azp' is invalid");
            }
        }

        if ($this->hasDefinedIssuer()) {
            if (! property_exists($token, 'iss')) {
                throw new InvalidJwtTokenException("Token 'iss' is not defined");
            }

            if ($token->iss !== $this->getExpectedIssuer()) {
                throw new InvalidJwtTokenException("Token 'iss' is invalid");
            }
        }
    }

    private function getExpectedIssuer(): string
    {
        return "$this->keycloakBaseUrl/realms/$this->realm";
    }

    private function hasDefinedIssuer(): bool
    {
        return ! empty($this->keycloakBaseUrl) && ! empty($this->realm);
    }
}
