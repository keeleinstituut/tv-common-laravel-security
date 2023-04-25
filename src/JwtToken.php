<?php

namespace KeycloakAuthGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class JwtToken
{
    /**
     * Decode a JWT token
     */
    public static function decode(string $token, string $publicKey = '', int $leeway = 0): ?stdClass
    {
        JWT::$leeway = $leeway;

        return JWT::decode($token, new Key(self::buildPublicKey($publicKey), 'RS256'));
    }

    /**
     * Build a valid public key from a string
     */
    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".
            wordwrap($key, 64, "\n", true).
            "\n-----END PUBLIC KEY-----";
    }
}
