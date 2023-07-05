# tv-common-laravel-security

This package helps you authenticate users on a Laravel API based on JWT tokens generated from  **Keycloak Server**.

The package is done using the next packages as basis:
- https://github.com/robsontenorio/laravel-keycloak-guard
- https://github.com/mariovalney/laravel-keycloak-web-guard

# Install

Add the next code into composer.json

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/keeleinstituut/tv-common-laravel-security"
    }
  ],
  "require": {
    "keeleinstituut/tv-common-laravel-security": "0.0.2"
  },
  "minimum-stability": "dev"
}
```

# Configuration

## Laravel Auth

You should add Keycloak auth guard to your `config/auth.php`.

Just add **keycloak** to "driver" option on configurations you want.

```php
'guards' => [
    'api' => [
        'driver' => 'keycloak',
        'provider' => 'users',
    ],

    // ...
],
```

If you would like to use the guard without `users` table change your provider config to:

```php
'providers' => [
    'users' => [
        'driver' => 'jwt-payload-users',
        'model' =>  KeycloakAuthGuard\Models\JwtPayloadUser::class,
    ],

    // ...
]
```

## Keycloak Guard

To configure the lib, publish the config file:

```bash
# Publish config file

php artisan vendor:publish  --provider="KeycloakAuthGuard\KeycloakAuthServiceProvider"
```

### Config parameters:

*  `REALM_PUBLIC_KEY_RETRIEVAL_MODE`

*Required. Default is `cached-api`*

Parameter defines the mode of how realm public key will be retrieved. Available options:
- `cached-api`
- `api`
- `config`

*  `KEYCLOAK_BASE_URL`

*Required for validation and in case if `REALM_PUBLIC_KEY_RETRIEVAL_MODE` equal to `api` or `cached-api`*

URL to keycloak. Format: https://your-keycloak-server.com/.

*  `KEYCLOAK_REALM`

*Required for validation and in case if `REALM_PUBLIC_KEY_RETRIEVAL_MODE` equal to `api` or `cached-api`*

Name of the keycloak realm.

*  `KEYCLOAK_REALM_PUBLIC_KEY`

*Default is `null`.*
*Required in case `REALM_PUBLIC_KEY_RETRIEVAL_MODE` equal to `config`*

The Keycloak Server realm public key (string). Application can auto fetch of realm public key and store it in the cache.

*  `KEYCLOAK_USER_PROVIDER_CREDENTIAL`

*Required in case of usage `Illuminate\Auth\EloquentUserProvider` as user provider. Default is `personal_identification_code`.*

The field from `users` table that contains the user unique identifier (eg.  username, email, nickname). This will be confronted against  `token_principal_attribute` attribute, while authenticating.

*  `KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE`

*Required in case of usage `Illuminate\Auth\EloquentUserProvider` as user provider. Default is `tolkevarav.personalIdentityCode`.*

The property from JWT token that contains the user identifier.
This will be confronted against  `user_provider_credential` attribute, while authenticating.

*  `KEYCLOAK_JWT_PAYLOAD_CUSTOM_CLAIMS_KEY`

*Used in case when `KeycloakAuthGuard\Auth\JwtPayloadUserProvider` configured as user provider. Default is `tolkevarav`*

The property from JWT token that contains the user metadata. In case of usage `KeycloakAuthGuard\Models\JwtPayloadUser` the lib expected the next structure of JWT token payload:
```php
[
    'iss' => '',
    'iat' => '',
    'sub' => '',
    ....
    'tolkevarav' => [ # <--- it's KEYCLOAK_JWT_PAYLOAD_CUSTOM_CLAIMS_KEY
        'personalIdentityCode' => '3430717934355',
        'userId' => '2ad53f6d-b876-4855-ae67-5d29b126c214',
        'institutionUserId' => 'e1057c3e-661f-4a23-8243-e770cb56bcb8',
        'forename' => 'Forename',
        'surname' => 'Surname',
        'privileges' => [
            'privilege_1',
            'privilege_2',
            'privilege_3',
        ],
        'selectedInstitution' => [
            'id' => '734f0f6c-ea6e-4c6a-ab77-6fa32044a0c4',
            'name' => 'Some Institution',
        ],
    ]
];
```

*  `REALM_PUBLIC_KEY_CACHE_TTL`

*Default is `86400`.*
Cache TTL for storing realm public key.

*  `KEYCLOAK_CACHE_DRIVER`

*Default is `redis`.*
name of the driver from app `config/cache.php` that will be used for storing the realm public key. 

*  `KEYCLOAK_LEEWAY`

*Default is `0`*.
    
 You can add a leeway to account for when there is a clock skew times between the signing and verifying servers.  If you are facing issues like *"Cannot handle token prior to <DATE>"* try to set it `60` (seconds).

*  `KEYCLOAK_TOKEN_INPUT_KEY`

*Default is `null`.*

By default, this package **always** will look at first for a `Bearer` token. Additionally, if this option is enabled, then it will try to get a token from this custom request param.

```php
// keycloak.php
'input_key' => 'api_token'

// If there is no Bearer token on request it will use `api_token` request param
GET  $this->get("/foo/secret?api_token=xxxxx")
POST $this->post("/foo/secret", ["api_token" => "xxxxx"])
```

# Privileges

You can check user has a role simply by `Auth::hasPrivilege('some-privilege')`;

# Middleware

You can check user against privilege using the `has-privilege` Middleware.

```php
$this->middleware('has-privilege:manage-something-cool');
```

# Tests

```php
composer test
```


