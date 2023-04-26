<?php

namespace KeycloakAuthGuard\Tests;

use Firebase\JWT\JWT;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use KeycloakAuthGuard\KeycloakAuthServiceProvider;
use KeycloakAuthGuard\Tests\Factories\UserFactory;
use KeycloakAuthGuard\Tests\Models\User;
use OpenSSLAsymmetricKey;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    public OpenSSLAsymmetricKey $privateKey;

    public string $publicKey;

    public array $payload;

    public string $token;

    protected function setUp(): void
    {
        // Prepare credentials
        $this->prepareCredentials();

        parent::setUp();

        $this->withoutExceptionHandling();

        // bootstrap
        $this->setUpDatabase($this->app);

        // Default user, same as jwt token
        $this->user = UserFactory::new()->create([
            'personal_identification_code' => '3430717934355',
        ]);
    }

    protected function prepareCredentials(): void
    {
        // Prepare private/public keys and a default JWT token, with a simple payload
        $this->privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        $this->payload = [
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
            ],
        ];

        $this->token = JWT::encode($this->payload, $this->privateKey, 'RS256');
    }

    // Default configs to make it running
    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('auth.guards.api', [
            'driver' => 'keycloak',
            'provider' => 'users',
        ]);

        $app['config']->set('keycloak', [
            'realm_public_key' => $this->plainPublicKey(),
            'jwt_payload_custom_claims_attribute' => 'tolkevarav',
            'realm_public_key_retrieval_mode' => 'config',
        ]);
    }

    protected function setUpDatabase(Application $app): void
    {
        $app['db']->connection()->getSchemaBuilder()->create('users', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('forename');
            $table->string('surname');
            $table->string('personal_identification_code');
            $table->timestamps();
        });
    }

    protected function getPackageProviders($app): array
    {
        Route::any(
            '/foo/public',
            'KeycloakAuthGuard\Tests\Controllers\FooController@public'
        );

        Route::any(
            '/foo/secret',
            'KeycloakAuthGuard\Tests\Controllers\FooController@secret'
        )->middleware(Authenticate::class);

        Route::any(
            '/foo/secret-with-privilege',
            'KeycloakAuthGuard\Tests\Controllers\FooController@superSecret'
        )->middleware('has-privilege:access_to_super_secret');

        return [KeycloakAuthServiceProvider::class];
    }

    // Just extract a string  from the public key, as required by config file
    protected function plainPublicKey(): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $this->publicKey);
        $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));

        return str_replace('\n', '', $string);
    }

    // Build a different token with custom payload
    protected function buildCustomToken(array $payload, string $keyId = null): void
    {
        $payload = array_replace($this->payload, $payload);

        $this->token = JWT::encode($payload, $this->privateKey, 'RS256', $keyId);
    }

    // Setup default token, for the default user
     public function withKeycloakToken(): self
     {
         $this->withToken($this->token);

         return $this;
     }
}
