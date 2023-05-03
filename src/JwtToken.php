<?php

namespace KeycloakAuthGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;
use UnexpectedValueException;

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

    public static function getHeader(string $jwt): stdClass
    {
        $tks = explode('.', $jwt);
        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        $headerBase64encoded = $tks[0];
        $headerRaw = JWT::urlsafeB64Decode($headerBase64encoded);
        if (null === ($header = JWT::jsonDecode($headerRaw))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        return $header;
    }
}
