<?php

namespace KeycloakAuthGuard\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class EnsureUserHasPrivilege
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): (Response) $next
     *
     * @throws AuthorizationException
     */
    public function handle(Request $request, Closure $next, string $privilege): Response
    {
        if (! Auth::hasPrivilege($privilege)) {
            throw new AuthorizationException("You don't have the '$privilege' privilege.", 403);
        }

        return $next($request);
    }
}
