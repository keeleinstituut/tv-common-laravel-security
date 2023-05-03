<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Facades\Config;
use RuntimeException;

class ApiRealmJwkRetriever implements RealmJwkRetrieverInterface
{
    private string $keycloakBaseUrl;

    private string $realm;

    public function __construct(private readonly ClientInterface $httpClient)
    {
        $this->keycloakBaseUrl = trim(Config::get('keycloak.base_url'), '/');
        $this->realm = Config::get('keycloak.realm');
    }

    public function getJwkOrJwks(?string $kid = null): Key|array
    {
        if (empty($kid)) {
            return JWK::parseKeySet($this->getJwksAsArray());
        }

        $jwks = $this->getJwksAsArray();
        foreach ($jwks['keys'] as $jwk) {
            if ($jwk['kid'] === $kid) {
                return JWK::parseKeySet(['keys' => [$jwk]]);
            }
        }

        throw new RuntimeException("jwk not found for the ID: $kid");
    }

    public function getJwksAsArray(): array
    {
        try {
            $response = $this->httpClient->request('GET', $this->getPublicKeyUrl());

            if ($response->getStatusCode() !== 200) {
                throw new RuntimeException('Public key retrieval failed. The keycloak response status code is '.$response->getStatusCode());
            }

            $responseJsonContent = $response->getBody()->getContents();
            $responseContent = json_decode($responseJsonContent, true);

            if (! isset($responseContent['keys'])) {
                throw new RuntimeException('Jwks retrieval failed');
            }

            return $responseContent;
        } catch (GuzzleException $e) {
            throw new RuntimeException('Jwks retrieval failed.', 0, $e);
        }
    }

    private function getPublicKeyUrl(): string
    {
        return "$this->keycloakBaseUrl/realms/$this->realm/protocol/openid-connect/certs";
    }
}
