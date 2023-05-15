<?php

namespace KeycloakAuthGuard\Exceptions;

use League\Config\Exception\InvalidConfigurationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

class InvalidJwtTokenPayloadException extends InvalidConfigurationException implements HttpExceptionInterface
{
    public function getStatusCode(): int
    {
        return Response::HTTP_UNAUTHORIZED;
    }

    public function getHeaders(): array
    {
        return [];
    }
}
