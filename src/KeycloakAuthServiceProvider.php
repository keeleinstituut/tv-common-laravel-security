<?php

namespace KeycloakAuthGuard;

use GuzzleHttp\Client;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use KeycloakAuthGuard\Auth\Guards\KeycloakGuard;
use KeycloakAuthGuard\Auth\JwtPayloadUserProvider;
use KeycloakAuthGuard\Middleware\EnsureJwtBelongsToServiceAccountWithSyncRole;
use KeycloakAuthGuard\Middleware\EnsureUserHasPrivilege;
use KeycloakAuthGuard\Services\ApiRealmJwkRetriever;
use KeycloakAuthGuard\Services\CachedRealmJwkRetriever;
use KeycloakAuthGuard\Services\CachedServiceAccountJwtRetriever;
use KeycloakAuthGuard\Services\ConfigRealmJwkRetriever;
use KeycloakAuthGuard\Services\Decoders\JwtTokenDecoder;
use KeycloakAuthGuard\Services\Decoders\RequestBasedJwtTokenDecoder;
use KeycloakAuthGuard\Services\RealmJwkRetrieverInterface;
use KeycloakAuthGuard\Services\ServiceAccountJwtRetriever;
use KeycloakAuthGuard\Services\ServiceAccountJwtRetrieverInterface;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use UnexpectedValueException;

class KeycloakAuthServiceProvider extends AuthServiceProvider
{
    public function boot()
    {
        $this->publishes([__DIR__.'/../config/keycloak.php' => config_path('keycloak.php')], 'config');
        $this->mergeConfigFrom(__DIR__.'/../config/keycloak.php', 'keycloak');

        Auth::provider('jwt-payload-users', function ($app, array $config) {
            return new JwtPayloadUserProvider($config['model']);
        });
    }

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function register()
    {
        $this->app->bind(RequestBasedJwtTokenDecoder::class, function (Application $app) {
            return new RequestBasedJwtTokenDecoder(
                new JwtTokenDecoder(
                    $this->getRealmPublicKeyRetriever()
                ),
                $app->get('request')
            );
        });

        $this->app->bind(ServiceAccountJwtRetrieverInterface::class, function (Application $app) {
            return new CachedServiceAccountJwtRetriever(
                new ServiceAccountJwtRetriever(
                    Config::get('keycloak.service_account_client_id'),
                    Config::get('keycloak.service_account_client_secret')
                ),
                $app->get('cache')->store(Config::get('keycloak.cache_store'))
            );
        });

        Auth::extend('keycloak', function (Application $app, $name, array $config) {
            return new KeycloakGuard(
                $app->make(RequestBasedJwtTokenDecoder::class),
                Auth::createUserProvider($config['provider']),
            );
        });

        $this->app->get('router')->aliasMiddleware('has-privilege', EnsureUserHasPrivilege::class);
        $this->app->get('router')->aliasMiddleware(
            'service-account-with-sync-role',
            EnsureJwtBelongsToServiceAccountWithSyncRole::class
        );
    }

    protected function getRealmPublicKeyRetriever(): RealmJwkRetrieverInterface
    {
        $mode = Config::get('keycloak.realm_public_key_retrieval_mode');

        return match ($mode) {
            'api' => new ApiRealmJwkRetriever(
                new Client(Config::get('keycloak.guzzle_options', []))
            ),
            'cached-api' => new CachedRealmJwkRetriever(
                new ApiRealmJwkRetriever(
                    new Client(Config::get('keycloak.guzzle_options', []))
                ),
                app('cache')->store(Config::get('keycloak.cache_store'))
            ),
            'config' => new ConfigRealmJwkRetriever(),
            default => throw new UnexpectedValueException("Unsupported value for realm_public_key_retrieval_mode: $mode")
        };
    }
}
