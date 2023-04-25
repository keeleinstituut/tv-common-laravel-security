<?php

namespace KeycloakAuthGuard\Services;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Facades\Config;
use RuntimeException;

class ApiRealmPublicKeyRetriever implements RealmPublicKeyRetrieverInterface
{
    private string $keycloakBaseUrl;

    private string $realm;

    public function __construct(private readonly ClientInterface $httpClient)
    {
        $this->keycloakBaseUrl = trim(Config::get('keycloak.base_url'), '/');
        $this->realm = Config::get('keycloak.realm');
    }

    public function getPublicKey(): string
    {
        try {
            $response = $this->httpClient->request('GET', $this->getPublicKeyUrl());

            if ($response->getStatusCode() !== 200) {
                throw new RuntimeException('Public key retrieval failed. The keycloak response status code is '.$response->getStatusCode());
            }

            $responseJsonContent = $response->getBody()->getContents();
            $responseContent = json_decode($responseJsonContent, true);

            if (! isset($responseContent['public_key'])) {
                throw new RuntimeException('Public key retrieval failed');
            }

            return $responseContent['public_key'];
        } catch (GuzzleException $e) {
            throw new RuntimeException('Public key retrieval failed.', 0, $e);
        }
    }

    private function getPublicKeyUrl(): string
    {
        return "$this->keycloakBaseUrl/realms/$this->realm";
    }
}
