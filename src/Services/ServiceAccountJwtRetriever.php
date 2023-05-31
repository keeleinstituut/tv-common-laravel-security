<?php

namespace KeycloakAuthGuard\Services;

use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

readonly class ServiceAccountJwtRetriever implements ServiceAccountJwtRetrieverInterface
{
    private string $keycloakBaseUrl;

    private string $realm;

    public function __construct(private string $clientId, private string $clientSecret)
    {
        $this->keycloakBaseUrl = trim(Config::get('keycloak.base_url'), '/');
        $this->realm = Config::get('keycloak.realm');
    }

    /**
     * @throws RequestException
     */
    public function getJwt(): string
    {
        return $this->getResponse()['access_token'];
    }

    /**
     * @throws RequestException
     */
    public function getResponse(): array
    {
        return Http::asForm()->post($this->getJwtRetrieveUrl(), [
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ])->throw()->json();
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    private function getJwtRetrieveUrl(): string
    {
        return "$this->keycloakBaseUrl/realms/$this->realm/protocol/openid-connect/token";
    }
}
