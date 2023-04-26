<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\Key;
use Illuminate\Support\Facades\Config;

class ConfigRealmJwkRetriever implements RealmJwkRetrieverInterface
{
    public function getJwkOrJwks(): Key|array
    {
        return new Key(self::buildPublicKey(Config::get('keycloak.realm_public_key')), 'RS256');
    }

    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".
            wordwrap($key, 64, "\n", true).
            "\n-----END PUBLIC KEY-----";
    }
}
