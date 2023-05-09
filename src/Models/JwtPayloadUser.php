<?php

namespace KeycloakAuthGuard\Models;

use BadMethodCallException;
use Illuminate\Contracts\Auth\Authenticatable;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenPayloadException;

readonly class JwtPayloadUser implements Authenticatable
{
    public string $id;

    public string $personalIdentificationCode;

    public string $institutionUserId;

    public string $institutionId;

    public string $institutionName;

    public string $forename;

    public string $surname;

    public array $privileges;

    public function __construct(array $jwtPayloadData)
    {
        $this->id = $jwtPayloadData['userId'] ?? '';
        $this->personalIdentificationCode = $jwtPayloadData['personalIdentificationCode'] ?? '';
        $this->forename = $jwtPayloadData['forename'] ?? '';
        $this->surname = $jwtPayloadData['surname'] ?? '';
        $this->privileges = $jwtPayloadData['privileges'] ?? [];

        $this->institutionUserId = $jwtPayloadData['institutionUserId'] ?? '';
        $this->institutionId = $jwtPayloadData['selectedInstitution']['id'] ?? '';
        $this->institutionName = $jwtPayloadData['selectedInstitution']['name'] ?? '';

        if (empty($this->id) || empty($this->personalIdentificationCode)) {
            throw new InvalidJwtTokenPayloadException('JWT token payload structure not match with configured user model');
        }
    }

    public function getAuthIdentifierName(): string
    {
        return 'institutionUserId';
    }

    public function getAuthIdentifier()
    {
        return $this->institutionUserId;
    }

    public function getAuthPassword(): string
    {
        throw new BadMethodCallException('Unexpected method [getAuthPassword] call');
    }

    public function getRememberToken(): string
    {
        throw new BadMethodCallException('Unexpected method [getRememberToken] call');
    }

    public function setRememberToken($value)
    {
        throw new BadMethodCallException('Unexpected method [setRememberToken] call');
    }

    public function getRememberTokenName(): string
    {
        throw new BadMethodCallException('Unexpected method [getRememberTokenName] call');
    }
}
