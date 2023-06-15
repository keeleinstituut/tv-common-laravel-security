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

        return $this->hasValidServiceAccountAzp($decodedJwt) && $this->hasSyncRole($decodedJwt);
    }

    private function hasSyncRole(stdClass $decodedJwt): bool
    {
        return isset($decodedJwt->realm_access->roles)
            && filled($decodedJwt->realm_access->roles)
            && is_array($decodedJwt->realm_access->roles)
            && filled(config('keycloak.service_account_sync_role'))
            && in_array(config('keycloak.service_account_sync_role'), $decodedJwt->realm_access->roles);
    }

    private function hasValidServiceAccountAzp(stdClass $decodedJwt): bool
    {
        if (! property_exists($decodedJwt, 'azp')) {
            return false;
        }

        $acceptedAuthorizedParties = explode(',', config('keycloak.service_accounts_accepted_authorized_parties'));
        if (! in_array($decodedJwt->azp, $acceptedAuthorizedParties)) {
            return false;
        }

        return true;
    }
}
