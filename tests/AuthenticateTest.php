<?php

namespace KeycloakAuthGuard\Tests;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Auth;
use KeycloakAuthGuard\Auth\Guards\KeycloakGuard;
use KeycloakAuthGuard\Auth\JwtPayloadUserProvider;
use KeycloakAuthGuard\Exceptions\InvalidJwtTokenException;
use KeycloakAuthGuard\Models\JwtPayloadUser;
use KeycloakAuthGuard\Services\ConfigRealmPublicKeyRetriever;

class AuthenticateTest extends TestCase
{
    public function test_authenticates_the_user_when_requesting_a_private_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);

        $this->withKeycloakToken()->json('POST', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);

        $this->withKeycloakToken()->json('PUT', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);

        $this->withKeycloakToken()->json('PATCH', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);

        $this->withKeycloakToken()->json('DELETE', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);
    }

    public function test_authenticates_the_user_when_requesting_an_public_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/public');

        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);
    }

    public function test_forbidden_when_request_a_protected_endpoint_without_token()
    {
        $this->expectException(AuthenticationException::class);
        $this->json('GET', '/foo/secret');
    }

    public function test_laravel_default_interface_for_authenticated_users()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals(true, Auth::hasUser());
        $this->assertEquals(false, Auth::guest());
        $this->assertEquals($this->user->id, Auth::id());
    }

    public function test_laravel_default_interface_for_unauthenticated_users()
    {
        $this->json('GET', '/foo/public');

        $this->assertEquals(false, Auth::hasUser());
        $this->assertEquals(true, Auth::guest());
        $this->assertEquals(null, Auth::id());
    }

    public function test_throws_a_exception_when_user_is_not_found()
    {
        $this->expectException(AuthenticationException::class);

        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentityCode' => 'some_code',
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_check_user_has_privilege_in_resource()
    {
        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
                'privileges' => [
                    'ADD_ROLE',
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasPrivilege('ADD_ROLE'));
    }

    public function test_middleware_with_corresponding_privilege()
    {
        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
                'privileges' => [
                    'access_to_super_secret',
                ],
            ],
        ]);

        $this->withKeycloakToken()
            ->json('GET', '/foo/secret-with-privilege')
            ->assertStatus(200);
    }

    public function test_middleware_without_corresponding_privilege()
    {
        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
                'privileges' => [
                    'not_so_secret',
                ],
            ],
        ]);

        $this->expectException(AuthorizationException::class);
        $this->withKeycloakToken()->json('GET', '/foo/secret-with-privilege');
    }

    public function test_check_user_no_has_privilege_in_resource()
    {
        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
                'privileges' => [
                    'ADD_ROLE',
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasPrivilege('SOME_PRIVILEGE'));
    }

    /**
     * @skip
     */
    public function test_custom_user_provider()
    {
        Auth::extend('keycloak', function ($app) {
            return new KeycloakGuard(
                new ConfigRealmPublicKeyRetriever(),
                new JwtPayloadUserProvider(JwtPayloadUser::class),
                $app->request
            );
        });

        $this->buildCustomToken([
            'tolkevarav' => [
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
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::user() instanceof JwtPayloadUser);
    }

    public function test_throws_a_exception_with_invalid_iat()
    {
        $this->expectException(InvalidJwtTokenException::class);

        $this->buildCustomToken([
            'iat' => time() + 30,   // time ahead in the future
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_works_with_leeway()
    {
        // Allows up to 60 seconds ahead in the  future
        config(['keycloak.leeway' => 60]);

        $this->buildCustomToken([
            'iat' => time() + 30, // time ahead in the future
            'tolkevarav' => [
                'personalIdentityCode' => '3430717934355',
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->personal_identification_code, Auth::user()->personal_identification_code);
    }

    public function test_authenticates_with_custom_input_key()
    {
        config(['keycloak.input_key' => 'api_token']);

        $this->json('GET', '/foo/secret?api_token='.$this->token);

        $this->assertEquals($this->user->id, Auth::id());

        $this->json('POST', '/foo/secret', ['api_token' => $this->token]);
    }

    public function test_authentication_prefers_bearer_token_over_with_custom_input_key()
    {
        config(['keycloak.input_key' => 'api_token']);

        $this->withKeycloakToken()->json('GET', '/foo/secret?api_token=some-junk');

        $this->assertEquals($this->user->id, Auth::id());

        $this->json('POST', '/foo/secret', ['api_token' => $this->token]);
    }
}
