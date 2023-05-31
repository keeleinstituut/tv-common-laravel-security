<?php

namespace KeycloakAuthGuard\Services;

use Illuminate\Cache\Repository;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Config;
use Psr\SimpleCache\InvalidArgumentException;

readonly class CachedServiceAccountJwtRetriever implements ServiceAccountJwtRetrieverInterface
{
    private string $realm;

    public function __construct(private ServiceAccountJwtRetriever $jwtRetriever, private Repository $repository)
    {
        $this->realm = Config::get('keycloak.realm');
    }

    /**
     * @throws RequestException
     * @throws InvalidArgumentException
     */
    public function getJwt(): string
    {
        if ($this->repository->has($this->getCacheKey())) {
            return $this->repository->get($this->getCacheKey());
        }

        $jwtResponse = $this->jwtRetriever->getResponse();
        $this->repository->set(
            $this->getCacheKey(),
            $jwtResponse['access_token'],
            $jwtResponse['expires_in']
        );

        return $jwtResponse['access_token'];
    }

    public function getCacheKey(): string
    {
        return "service-account-$this->realm-{$this->jwtRetriever->getClientId()}-jwt";
    }
}
