<?php

namespace KeycloakAuthGuard\Services;

use Illuminate\Support\Facades\Config;

class ConfigRealmPublicKeyRetriever implements RealmPublicKeyRetrieverInterface
{
    public function getPublicKey(): string
    {
        return Config::get('keycloak.realm_public_key');
    }
}