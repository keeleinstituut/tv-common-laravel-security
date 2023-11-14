<?php

namespace KeycloakAuthGuard\Services\Decoders;

use Illuminate\Http\Request;
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
        return $this->getDecodedJwtWithSpecifiedValidation(true, true);
    }

    public function getDecodedJwtWithSpecifiedValidation(bool $validateAzp, bool $validateIss, bool $validateExpiry = true): ?stdClass
    {
        if (! $token = $this->getToken()) {
            return null;
        }

        return $this->decodeJwtWithSpecifiedValidation($token, $validateAzp, $validateIss, $validateExpiry);
    }

    public function decodeJwtWithSpecifiedValidation(string $jwt, bool $validateAzp, bool $validateIss, bool $validateExpiry = true): ?stdClass
    {
        return $this->decoder->decodeWithSpecifiedValidation($jwt, $validateAzp, $validateIss, $validateExpiry);
    }

    /**
     * Get the token for the current request.
     */
    public function getToken(): string
    {
        if (! empty($this->request->bearerToken())) {
            return $this->request->bearerToken();
        }

        if (! empty(config('keycloak.input_key', ''))) {
            return $this->request->input(
                config('keycloak.input_key')
            );
        }

        return '';
    }
}
