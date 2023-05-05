<?php

namespace KeycloakAuthGuard\Tests\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class FooController extends BaseController
{
    use AuthorizesRequests;

    public function secret(Request $request): string
    {
        return 'protected';
    }

    public function superSecret(Request $request): string
    {
        return 'protected with privilege';
    }

    public function public(Request $request): string
    {
        return 'public';
    }
}
