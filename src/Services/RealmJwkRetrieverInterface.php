<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\Key;

interface RealmJwkRetrieverInterface
{
    public function getJwkOrJwks(): Key|array;
}
