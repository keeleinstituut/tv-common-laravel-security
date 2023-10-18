<?php

namespace KeycloakAuthGuard\Auth\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Arr;
use KeycloakAuthGuard\Auth\JwtPayloadUserProvider;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Services\Decoders\RequestBasedJwtTokenDecoder;
use stdClass;

class KeycloakGuard implements Guard
{
    private ?Authenticatable $user;

    private ?stdClass $decodedToken;

    /**
     * The user we last attempted to retrieve.
     */
    protected ?Authenticatable $lastAttempted;

    public function __construct(
        private readonly RequestBasedJwtTokenDecoder $decoder,
        private readonly UserProvider $provider,
    ) {
        $this->user = null;
        $this->decodedToken = null;
        $this->authenticate();
    }

    /**
     * Decode token, validate and authenticate user
     *
     * @throws InvalidJwtTokenException
     */
    private function authenticate(): void
    {
        $this->decodedToken = $this->decoder->getDecodedJwt();
        if ($this->decodedToken && $this->validate($this->getUserCredentials())) {
            $this->setUser($this->lastAttempted);
        }
    }

    /**
     * Get the user credentials for retrieving of the user.
     */
    private function getUserCredentials(): array
    {
        if ($this->provider instanceof JwtPayloadUserProvider) {
            return $this->getCustomClaimsTokenData();
        }

        return [
            config('keycloak.user_provider_credential') => $this->getTokenPayloadData(config('keycloak.token_principal_attribute')),
        ];
    }

    public function getCustomClaimsTokenData(string $key = null, mixed $default = null): mixed
    {
        $customClaimsKey = config('keycloak.jwt_payload_custom_claims_attribute');
        $customClaimsTokenData = $this->getTokenPayloadData($customClaimsKey, []);

        if (empty($key)) {
            return $customClaimsTokenData;
        }

        return Arr::get($customClaimsTokenData, $key, $default);
    }

    private function getTokenPayloadData(string $key = null, $default = null): mixed
    {
        $tokenData = json_decode($this->token(), true);

        if (empty($key)) {
            return $tokenData;
        }

        return Arr::get($tokenData, $key, $default);
    }

    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool
    {
        return ! is_null($this->user());
    }

    /**
     * Determine if the guard has a user instance.
     */
    public function hasUser(): bool
    {
        return ! is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Set the current user.
     */
    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?Authenticatable
    {
        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): ?string
    {
        return $this->user()?->getAuthIdentifier();
    }

    /**
     * Returns full decoded JWT token from authenticated user
     */
    public function token(): ?string
    {
        return json_encode($this->decodedToken);
    }

    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $this->provider->retrieveByCredentials($credentials);

        return ! empty($this->lastAttempted);
    }

    /**
     * Check if authenticated user has a specific privilege
     */
    public function hasPrivilege(string $privilege): bool
    {
        $privileges = $this->getCustomClaimsTokenData('privileges', []);

        return in_array($privilege, $privileges);
    }
}
