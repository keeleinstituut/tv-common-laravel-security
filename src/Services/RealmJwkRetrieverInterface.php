<?php

namespace KeycloakAuthGuard\Services;

use Firebase\JWT\Key;

interface RealmJwkRetrieverInterface
{
    public function getJwkOrJwks(?string $kid = null): Key|array;
}
