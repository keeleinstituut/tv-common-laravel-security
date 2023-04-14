<?php

namespace KeycloakAuthGuard\Auth\Guards;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use KeycloakAuthGuard\Auth\JwtPayloadUserProvider;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Exceptions\UserNotFoundException;
use KeycloakAuthGuard\JwtToken;
use KeycloakAuthGuard\Services\RealmPublicKeyRetrieverInterface;
use stdClass;

class KeycloakGuard implements Guard
{
    private ?Authenticatable $user;
    private ?stdClass $decodedToken;

    /**
     * @param RealmPublicKeyRetrieverInterface $publicKeyRetriever
     * @param UserProvider $provider
     * @param Request $request
     */
    public function __construct(
        private readonly RealmPublicKeyRetrieverInterface $publicKeyRetriever,
        private readonly UserProvider                     $provider,
        private readonly Request                          $request
    )
    {
        $this->user = null;
        $this->decodedToken = null;
        $this->authenticate();
    }

    /**
     * Decode token, validate and authenticate user
     *
     * @return void
     * @throws InvalidJwtTokenException
     */
    private function authenticate(): void
    {
        try {
            $this->decodedToken = JwtToken::decode(
                $this->getTokenForRequest(),
                $this->publicKeyRetriever->getPublicKey(),
                Config::get('keycloak.leeway')
            );
        } catch (Exception $e) {
            throw new InvalidJwtTokenException($e->getMessage());
        }

        if ($this->decodedToken) {
            $this->validate($this->getUserCredentials());
        }
    }

    /**
     * Get the token for the current request.
     *
     * @return string
     */
    private function getTokenForRequest(): string
    {
        if (!empty($this->request->bearerToken())) {
            return $this->request->bearerToken();
        }

        if (!empty(Config::get('keycloak.input_key', ''))) {
            return $this->request->input(
                Config::get('keycloak.input_key', '')
            );
        }

        return '';
    }

    /**
     * Get the user credentials for retrieving of the user.
     *
     * @return array
     */
    private function getUserCredentials(): array
    {
        if ($this->provider instanceof JwtPayloadUserProvider) {
            return $this->getCustomClaimsTokenData();
        }

        return [
            Config::get('keycloak.user_provider_credential') => $this->getTokenPayloadData(Config::get('keycloak.token_principal_attribute'))
        ];
    }

    private function getCustomClaimsTokenData(string $key = null, mixed $default = null): mixed
    {
        $customClaimsKey = Config::get('keycloak.jwt_payload_custom_claims_attribute');
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
     *
     * @return bool
     */
    public function check(): bool
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser(): bool
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Set the current user.
     *
     * @param Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|null
     */
    public function user(): ?Authenticatable
    {
        if (is_null($this->user)) {
            return null;
        }

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return string|null
     */
    public function id(): ?string
    {
        if (!$this->hasUser()) {
            return null;
        }

        return $this->user()->getAuthIdentifier();
    }

    /**
     * Returns full decoded JWT token from authenticated user
     *
     * @return string|null
     */
    public function token(): ?string
    {
        return json_encode($this->decodedToken);
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        if (!$user = $this->provider->retrieveByCredentials($credentials)) {
            throw new UserNotFoundException("User not found. Credentials: " . json_encode($credentials));
        }

        $this->setUser($user);

        return true;
    }

    /**
     * Check if authenticated user has a specific privilege
     * @param string $privilege
     * @return bool
     */
    public function hasPrivilege(string $privilege): bool
    {
        $privileges = $this->getCustomClaimsTokenData('privileges', []);
        return in_array($privilege, $privileges);
    }
}
