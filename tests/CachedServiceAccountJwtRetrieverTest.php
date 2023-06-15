<?php

namespace KeycloakAuthGuard\Tests;

use Illuminate\Cache\Repository;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Exceptions\TooShortJwtLifetimeException;
use KeycloakAuthGuard\Services\CachedServiceAccountJwtRetriever;
use KeycloakAuthGuard\Services\ConfigRealmJwkRetriever;
use KeycloakAuthGuard\Services\Decoders\JwtTokenDecoder;
use KeycloakAuthGuard\Services\ServiceAccountJwtRetriever;
use Psr\SimpleCache\InvalidArgumentException;
use RuntimeException;

class CachedServiceAccountJwtRetrieverTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('keycloak', [
            'base_url' => 'http://localhost',
            'realm' => 'master',
            'accepted_authorized_parties' => 'tolkevarav-web-dev,tolkevarav-web-dev1',
            'service_account_jwt_cache_expiry_delay' => 10,
            'realm_public_key' => $this->plainPublicKey(),
        ]);
    }

    /**
     * @throws RequestException
     * @throws InvalidArgumentException
     */
    public function test_receiving_and_caching_of_service_account_jwt()
    {
        Http::fake(fn() => Http::response($this->getServiceAccountObtainJwtResponse()));

        $retriever = $this->getJwtRetriever();
        $jwt = $retriever->getJwt();

        $cacheStorage = $this->getCacheRepository();
        $this->assertEquals($this->getServiceAccountObtainJwtResponse()['access_token'], $jwt);
        $this->assertTrue($cacheStorage->has($retriever->getCacheKey()));
        $this->assertEquals($cacheStorage->get($retriever->getCacheKey()), $jwt);
    }

    /**
     * @throws RequestException
     * @throws InvalidArgumentException
     */
    public function test_caching_of_service_account_jwt_that_will_expire_soon()
    {
        $cacheExpiryDelay = config('keycloak.service_account_jwt_cache_expiry_delay') - 1;
        Http::fake(fn() => Http::response($this->getServiceAccountObtainJwtResponse($cacheExpiryDelay)));
        $this->expectException(TooShortJwtLifetimeException::class);
        $this->getJwtRetriever()->getJwt();
    }

    /**
     * @throws RequestException
     * @throws InvalidArgumentException
     */
    public function test_caching_of_service_account_without_exp_claim()
    {
        $this->buildCustomToken([]);
        Http::fake(fn() => Http::response([
            'access_token' => $this->token,
            'expires_in' => 300,
        ]));
        $this->expectException(InvalidJwtTokenException::class);
        $this->getJwtRetriever()->getJwt();
    }

    private function getJwtRetriever(): CachedServiceAccountJwtRetriever
    {
        return new CachedServiceAccountJwtRetriever(
            new ServiceAccountJwtRetriever('', ''),
            new JwtTokenDecoder(
                new ConfigRealmJwkRetriever()
            ),
            $this->getCacheRepository()
        );
    }

    private function getServiceAccountObtainJwtResponse(int $expiresIn = 100): array
    {
        $this->buildCustomToken([
            'exp' => time() + $expiresIn,
        ]);

        return [
            'access_token' => $this->token,
            'expires_in' => 300,
        ];
    }

    private function getCacheRepository(): Repository
    {
        return app('cache')->store('array');
    }
}
