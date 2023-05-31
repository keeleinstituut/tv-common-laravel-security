<?php

namespace KeycloakAuthGuard\Services;

interface ServiceAccountJwtRetrieverInterface
{
    public function getJwt(): string;
}
