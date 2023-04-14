<?php

namespace KeycloakAuthGuard;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use KeycloakAuthGuard\Auth\Guards\KeycloakGuard;
use KeycloakAuthGuard\Auth\JwtPayloadUserProvider;
use KeycloakAuthGuard\Middleware\EnsureUserHasPrivilege;
use KeycloakAuthGuard\Services\ApiRealmPublicKeyRetriever;
use KeycloakAuthGuard\Services\CachedRealmPublicKeyRetriever;
use GuzzleHttp\Client;
use KeycloakAuthGuard\Services\ConfigRealmPublicKeyRetriever;
use KeycloakAuthGuard\Services\RealmPublicKeyRetrieverInterface;

class KeycloakAuthServiceProvider extends AuthServiceProvider
{
    public function boot()
    {
        $this->publishes([__DIR__ . '/../config/keycloak.php' => config_path('keycloak.php')], 'config');
        $this->mergeConfigFrom(__DIR__ . '/../config/keycloak.php', 'keycloak');

        Auth::provider('jwt-payload-users', function ($app, array $config) {
            return new JwtPayloadUserProvider($config['model']);
        });
    }

    public function register()
    {
        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(
                $this->getRealmPublicKeyRetriever(),
                Auth::createUserProvider($config['provider']),
                $app->request
            );
        });

        $this->app['router']->aliasMiddleware('has-privilege', EnsureUserHasPrivilege::class);
    }

    protected function getRealmPublicKeyRetriever(): RealmPublicKeyRetrieverInterface
    {
        return match (Config::get('keycloak.realm_public_key_retrieval_mode')) {
            'api' => new ApiRealmPublicKeyRetriever(
                new Client(Config::get('keycloak.guzzle_options', []))
            ),
            'cached-api' => new CachedRealmPublicKeyRetriever(
                new ApiRealmPublicKeyRetriever(
                    new Client(Config::get('keycloak.guzzle_options', []))
                ),
                app('cache')->store(Config::get('keycloak.realm_public_key_cache_store'))
            ),
            default => new ConfigRealmPublicKeyRetriever()
        };
    }
}
