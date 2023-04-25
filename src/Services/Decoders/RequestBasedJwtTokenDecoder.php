<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use stdClass;

readonly class RequestBasedJwtTokenDecoder
{
    public function __construct(
        private JwtTokenDecoder $decoder,
        private Request $request
    ) {
    }

    public function getDecodedJwt(): ?stdClass
    {
        if (! $token = $this->getToken()) {
            return null;
        }

        return $this->decoder->decode($token);
    }

    /**
     * Get the token for the current request.
     */
    public function getToken(): string
    {
        if (! empty($this->request->bearerToken())) {
            return $this->request->bearerToken();
        }

        if (! empty(Config::get('keycloak.input_key', ''))) {
            return $this->request->input(
                Config::get('keycloak.input_key')
            );
        }

        return '';
    }
}
