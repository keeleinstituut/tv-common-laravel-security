<?php

namespace KeycloakAuthGuard\Exceptions;

use Nette\InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

class InvalidJwtTokenException extends InvalidArgumentException implements HttpExceptionInterface
{
    public function getStatusCode(): int
    {
        return Response::HTTP_FORBIDDEN;
    }

    public function getHeaders(): array
    {
        return [];
    }
}
