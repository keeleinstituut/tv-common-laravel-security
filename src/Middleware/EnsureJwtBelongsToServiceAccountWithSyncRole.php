<?php

namespace KeycloakAuthGuard\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use KeycloakAuthGuard\Services\Decoders\RequestBasedJwtTokenDecoder;
use stdClass;
use Symfony\Component\HttpFoundation\Response;

readonly class EnsureJwtBelongsToServiceAccountWithSyncRole
{
    public function __construct(private RequestBasedJwtTokenDecoder $jwtDecoder)
    {
    }

    /**
     * @throws AuthorizationException
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->isAuthorized()) {
            throw new AuthorizationException("You don't have the corresponding role to perform the action", 403);
        }

        return $next($request);
    }

    private function isAuthorized(): bool
    {
        $decodedJwt = $this->jwtDecoder->getDecodedJwtWithSpecifiedValidation(false, true);

        abort_if(empty($decodedJwt), 401);
        return $this->hasSyncRole($decodedJwt);
    }

    public function jwtHasRealmRole(string $jwt, string $realmRole): bool
    {
        $decodedJwt = $this->jwtDecoder->decodeJwtWithSpecifiedValidation($jwt, false, true, false);

        abort_if(empty($decodedJwt), 401);
        return $this->hasRealmRole($decodedJwt, $realmRole);
    }

    private function hasRealmRole(stdClass $decodedJwt, string $realmRole) {
        return isset($decodedJwt->realm_access->roles)
            && filled($decodedJwt->realm_access->roles)
            && is_array($decodedJwt->realm_access->roles)
            && filled($realmRole)
            && in_array($realmRole, $decodedJwt->realm_access->roles);
    }

    private function hasSyncRole(stdClass $decodedJwt): bool
    {
        return $this->hasRealmRole($decodedJwt, config('keycloak.service_account_sync_role'));
    }
}
