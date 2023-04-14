<?php

namespace KeycloakAuthGuard\Services;

interface RealmPublicKeyRetrieverInterface
{
    public function getPublicKey(): string;
}