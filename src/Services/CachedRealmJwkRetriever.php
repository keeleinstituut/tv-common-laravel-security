<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Cache\Repository;
use Psr\SimpleCache\InvalidArgumentException;

class CachedRealmJwkRetriever implements RealmJwkRetrieverInterface
{
    private string $realm;

    public function __construct(private readonly ApiRealmJwkRetriever $apiRetriever, private readonly Repository $repository)
    {
        $this->realm = config('keycloak.realm');
    }

    /**
     * @throws InvalidArgumentException
     */
    public function getJwkOrJwks(?string $kid = null): Key|array
    {
        if ($this->repository->has($this->getCacheKey($kid))) {
            $jwks = $this->repository->get($this->getCacheKey($kid));

            return JWK::parseKeySet(json_decode($jwks, true));
        }

        $jwks = $this->apiRetriever->getJwksAsArray();
        foreach ($jwks['keys'] as $jwk) {
            $this->repository->set(
                $this->getCacheKey($jwk['kid']),
                json_encode(['keys' => [$jwk]]),
                $this->getCacheTTL()
            );
        }

        return JWK::parseKeySet($jwks);
    }

    private function getCacheKey(?string $kid = null): string
    {
        return "$this->realm-realm-jwk-$kid";
    }

    private function getCacheTTL(): int
    {
        return config('keycloak.realm_public_key_cache_ttl');
    }
}
