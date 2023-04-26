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
    public static function decode(string $token, Key|array $jwkOrJwks, int $leeway = 0): ?stdClass
    {
        JWT::$leeway = $leeway;

        return JWT::decode($token, $jwkOrJwks);
    }
}
