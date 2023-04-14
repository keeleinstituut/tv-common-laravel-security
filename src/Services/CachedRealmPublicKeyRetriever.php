<?php

namespace KeycloakAuthGuard\Services;

use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Config;

class CachedRealmPublicKeyRetriever implements RealmPublicKeyRetrieverInterface
{
    private string $realm;

    public function __construct(private readonly RealmPublicKeyRetrieverInterface $provider, private readonly Repository $repository)
    {
        $this->realm = Config::get('keycloak.realm');
    }

    public function getPublicKey(): string
    {
        if ($this->repository->has($this->getCacheKey())) {
            return $this->repository->get($this->getCacheKey());
        }

        $publicKey = $this->provider->getPublicKey();

        $this->repository->set(
            $this->getCacheKey(),
            $publicKey,
            $this->getCacheTTL()
        );

        return $publicKey;
    }

    private function getCacheKey(): string
    {
        return "$this->realm-realm-public-key";
    }

    private function getCacheTTL(): int
    {
        return Config::get('keycloak.realm_public_key_cache_ttl', 1);
    }
}