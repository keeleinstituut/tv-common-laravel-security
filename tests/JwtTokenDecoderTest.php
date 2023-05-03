<?php

namespace KeycloakAuthGuard\Tests;

use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Services\ConfigRealmJwkRetriever;
use KeycloakAuthGuard\Services\Decoders\JwtTokenDecoder;

class JwtTokenDecoderTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('keycloak', [
            'base_url' => 'http://localhost',
            'realm' => 'master',
            'accepted_authorized_parties' => 'tolkevarav-web-dev,tolkevarav-web-dev1',
            'realm_public_key' => $this->plainPublicKey(),
        ]);
    }

    public function test_successful_validation()
    {
        $this->buildCustomToken([
            'custom-claim-key' => 'custom-claim-value',
            'iss' => 'http://localhost/realms/master',
            'azp' => 'tolkevarav-web-dev',
        ]);

        $decoder = new JwtTokenDecoder(
            new ConfigRealmJwkRetriever()
        );

        $decodedToken = $decoder->decode($this->token);

        $this->assertObjectHasProperty('iss', $decodedToken);
        $this->assertObjectHasProperty('azp', $decodedToken);

        $this->assertEquals('http://localhost/realms/master', $decodedToken->iss);
        $this->assertEquals('tolkevarav-web-dev', $decodedToken->azp);
    }

    public function test_multiple_azp()
    {
        $this->buildCustomToken([
            'custom-claim-key' => 'custom-claim-value',
            'iss' => 'http://localhost/realms/master',
            'azp' => 'tolkevarav-web-dev',
        ]);

        $decoder = new JwtTokenDecoder(
            new ConfigRealmJwkRetriever()
        );

        $decodedToken = $decoder->decode($this->token);

        $this->assertObjectHasProperty('iss', $decodedToken);
        $this->assertObjectHasProperty('azp', $decodedToken);

        $this->assertEquals('http://localhost/realms/master', $decodedToken->iss);
        $this->assertEquals('tolkevarav-web-dev', $decodedToken->azp);
    }

    public function test_invalid_azp()
    {
        $this->expectException(InvalidJwtTokenException::class);

        $this->buildCustomToken([
            'custom-claim-key' => 'custom-claim-value',
            'iss' => 'http://localhost/realms/master',
            'azp' => 'invalid-azp',
        ]);

        $decoder = new JwtTokenDecoder(
            new ConfigRealmJwkRetriever()
        );

        $decoder->decode($this->token);
    }

    public function test_invalid_issuer()
    {
        $this->expectException(InvalidJwtTokenException::class);

        $this->buildCustomToken([
            'custom-claim-key' => 'custom-claim-value',
            'iss' => 'http://invalid.issuer',
            'azp' => 'tolkevarav-web-dev',
        ]);

        $decoder = new JwtTokenDecoder(
            new ConfigRealmJwkRetriever()
        );

        $decoder->decode($this->token);
    }
}