<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Exception;
use Illuminate\Support\Facades\Config;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\JwtToken;
use KeycloakAuthGuard\Services\RealmPublicKeyRetrieverInterface;
use stdClass;

readonly class JwtTokenDecoder
{
    public function __construct(private RealmPublicKeyRetrieverInterface $publicKeyRetriever)
    {
    }

    public function decode(string $token): ?stdClass
    {
        try {
            $token = JwtToken::decode(
                $token,
                $this->publicKeyRetriever->getPublicKey(),
                Config::get('keycloak.leeway')
            );
        } catch (Exception $e) {
            throw new InvalidJwtTokenException('JWT token is invalid', 0, $e);
        }

        if (empty($token)) {
            return null;
        }

        return $token;
    }
}
