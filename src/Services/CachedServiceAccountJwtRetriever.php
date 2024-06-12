<?php

namespace KeycloakAuthGuard\Services;

use Illuminate\Cache\Repository;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Log;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Exceptions\TooShortJwtLifetimeException;
use KeycloakAuthGuard\Services\Decoders\JwtTokenDecoder;
use Psr\SimpleCache\InvalidArgumentException;
use Exception;

readonly class CachedServiceAccountJwtRetriever implements ServiceAccountJwtRetrieverInterface
{
    private string $realm;

    private int $cacheExpiryDelay;

    public function __construct(private ServiceAccountJwtRetriever $jwtRetriever, private JwtTokenDecoder $decoder, private Repository $repository)
    {
        $this->realm = config('keycloak.realm');
        $this->cacheExpiryDelay = config('keycloak.service_account_jwt_cache_expiry_delay');
    }

    /**
     * @throws RequestException
     * @throws InvalidArgumentException
     */
    public function getJwt(): string
    {
        try {
            if ($this->repository->has($this->getCacheKey())) {
                return $this->repository->get($this->getCacheKey());
            }
        } catch (Exception $e) {
            // in case if connection is lost we will try to fetch it
            Log::error('Retrieving of service account JWT from cache failed: ' . $e->getMessage());
            report($e);
        }

        $jwtResponse = $this->jwtRetriever->sendClientCredentialsGrantRequest();

        try {
            $this->repository->set(
                $this->getCacheKey(),
                $jwtResponse['access_token'],
                $this->getCacheTTL($jwtResponse)
            );
        } catch (Exception $e) {
            Log::error('Storing of service account JWT in cache failed: ' . $e->getMessage());
            report($e);
        }

        return $jwtResponse['access_token'];
    }

    public function getCacheKey(): string
    {
        return "service-account-$this->realm-{$this->jwtRetriever->getClientId()}-jwt";
    }

    private function getCacheTTL(array $response): int
    {
        $decodedToken = $this->decoder->decodeWithSpecifiedValidation(
            $response['access_token'],
            false,
            true
        );

        if (isset($decodedToken->exp) && filled($decodedToken->exp)) {
            if (($ttl = $decodedToken->exp - time()) < $this->cacheExpiryDelay) {
                throw new TooShortJwtLifetimeException('Token expiration less that cache expiry delay');
            }

            return $ttl - $this->cacheExpiryDelay;
        }

        throw new InvalidJwtTokenException("Token 'exp' is not defined");
    }
}
