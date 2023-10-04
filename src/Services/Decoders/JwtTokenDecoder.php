<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Exception;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\JwtToken;
use KeycloakAuthGuard\Services\CachedRealmJwkRetriever;
use KeycloakAuthGuard\Services\RealmJwkRetrieverInterface;
use stdClass;

readonly class JwtTokenDecoder
{
    private string $keycloakBaseUrl;

    private string $realm;

    private int $leeway;

    public function __construct(private RealmJwkRetrieverInterface $jwkRetriever)
    {
        $this->keycloakBaseUrl = trim(config('keycloak.base_url'), '/');
        $this->realm = config('keycloak.realm');
        $this->leeway = config('keycloak.leeway');
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
        } catch (Exception $e) {
            throw new InvalidJwtTokenException("Retrieving of JWT token 'kid' is failed", 0, $e);
        }

        $decodedToken = $this->getDecodedToken($token, $kid);

        $this->validate($decodedToken, $validateAzp, $validateIss);

        return $decodedToken;
    }

    /**
     * @throws InvalidJwtTokenException
     */
    private function validate(?stdClass $token, bool $validateAzp, bool $validateIss): void
    {
        if (empty($token)) {
            throw new InvalidJwtTokenException('Token decode returned empty result');
        }

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

    private function getDecodedToken(string $token, ?string $kid, bool $cacheRefreshed = false): ?stdClass
    {
        try {
            return JwtToken::decode(
                $token,
                $this->jwkRetriever->getJwkOrJwks($kid),
                $this->leeway
            );
        } catch (Exception $e) {
            if ($this->jwkRetriever instanceof CachedRealmJwkRetriever && ! $cacheRefreshed) {
                $this->jwkRetriever->cleanupCache($kid);

                return $this->getDecodedToken($token, $kid, true);
            }

            throw new InvalidJwtTokenException('JWT token is invalid', 0, $e);
        }
    }
}
