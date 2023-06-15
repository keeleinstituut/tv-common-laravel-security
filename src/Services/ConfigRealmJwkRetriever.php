<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\Key;

class ConfigRealmJwkRetriever implements RealmJwkRetrieverInterface
{
    public function getJwkOrJwks(?string $kid = null): Key|array
    {
        return new Key(self::buildPublicKey(config('keycloak.realm_public_key')), 'RS256');
    }

    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".
            wordwrap($key, 64, "\n", true).
            "\n-----END PUBLIC KEY-----";
    }
}
