<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Config;
use Psr\SimpleCache\InvalidArgumentException;

class CachedRealmJwkRetriever implements RealmJwkRetrieverInterface
{
    private string $realm;

    public function __construct(private readonly ApiRealmJwkRetriever $apiRetriever, private readonly Repository $repository)
    {
        $this->realm = Config::get('keycloak.realm');
    }

    /**
     * @throws InvalidArgumentException
     */
    public function getJwkOrJwks(): Key|array
    {
        if ($this->repository->has($this->getCacheKey())) {
            $jwks = $this->repository->get($this->getCacheKey());

            return JWK::parseKeySet(json_decode($jwks));
        }

        $jwks = $this->apiRetriever->getJwksAsArray();

        $this->repository->set(
            $this->getCacheKey(),
            json_encode($jwks),
            $this->getCacheTTL()
        );

        return JWK::parseKeySet($jwks);
    }

    private function getCacheKey(): string
    {
        return "$this->realm-realm-jwks";
    }

    private function getCacheTTL(): int
    {
        return Config::get('keycloak.realm_public_key_cache_ttl');
    }
}
