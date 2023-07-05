<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Exception;
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
        $this->keycloakBaseUrl = trim(config('keycloak.base_url'), '/');
        $this->realm = config('keycloak.realm');
    }

    /**
     * @throws InvalidJwtTokenException
     */
    public function decode(string $token): ?stdClass
    {
        return $this->decodeWithSpecifiedValidation($token, true, true);
    }

    /**
     * @throws InvalidJwtTokenException
     */
    public function decodeWithSpecifiedValidation(string $token, bool $validateAzp, bool $validateIss): ?stdClass
    {
        try {
            $kid = JwtToken::getHeader($token)->kid ?? null;
            $token = JwtToken::decode(
                $token,
                $this->jwkRetriever->getJwkOrJwks($kid),
                config('keycloak.leeway')
            );
        } catch (Exception $e) {
            throw new InvalidJwtTokenException('JWT token is invalid', 0, $e);
        }

        if (empty($token)) {
            return null;
        }

        $this->validate($token, $validateAzp, $validateIss);

        return $token;
    }

    /**
     * @throws InvalidJwtTokenException
     */
    private function validate(stdClass $token, bool $validateAzp, bool $validateIss): void
    {
        if ($validateAzp) {
            $acceptedAuthorizedParties = explode(',', config('keycloak.accepted_authorized_parties'));
            if (! property_exists($token, 'azp')) {
                throw new InvalidJwtTokenException("Token 'azp' is not defined");
            }

            if (! in_array($token->azp, $acceptedAuthorizedParties)) {
                throw new InvalidJwtTokenException("Token 'azp' is invalid");
            }
        }

        if ($validateIss) {
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
}
