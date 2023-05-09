<?php

namespace KeycloakAuthGuard\Tests;

use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use KeycloakAuthGuard\Services\ApiRealmJwkRetriever;
use KeycloakAuthGuard\Services\CachedRealmJwkRetriever;

class ApiRealmJwkRetrieverTest extends TestCase
{
    public function test_receiving_of_jwks()
    {
        $keyId = 'some-id';
        $retriever = new CachedRealmJwkRetriever(
            new ApiRealmJwkRetriever(
                $this->givenHttpClientWithSuccessfulResponse(
                    json_encode($this->buildJwks($keyId))
                )
            ),
            app('cache')->store('array')
        );

        /** @var CachedKeySet $publicKeySet */
        $keySet = $retriever->getJwkOrJwks($keyId);
        $this->assertArrayHasKey($keyId, $keySet);

        $this->buildCustomToken([
            'tolkevarav' => [
                'personalIdentificationCode' => 'some_code',
            ],
        ], $keyId);
        $decodedToken = JWT::decode($this->token, $keySet);
        $this->assertObjectHasProperty('tolkevarav', $decodedToken);
    }

    private function givenHttpClientWithSuccessfulResponse(string $responseBody): ClientInterface
    {
        $mock = new MockHandler([
            new Response(200, [], $responseBody),
        ]);

        $handlerStack = HandlerStack::create($mock);

        return new Client(['handler' => $handlerStack]);
    }

    private function buildJwks(string $keyId): array
    {
        $publicKey = openssl_pkey_get_public($this->publicKey);
        $privateKey = openssl_pkey_get_private($this->privateKey);

        $dn = [
            'commonName' => 'example.com',
            'emailAddress' => 'some@email.com',
        ];
        $csr = openssl_csr_new($dn, $privateKey, ['digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365);
        $chain = [openssl_x509_read($cert)];

        $x5c = [];
        foreach ($chain as $chainCert) {
            $certData = null;
            openssl_x509_export($chainCert, $certData);
            $certData = str_replace("\n", '', $certData);
            $x5c[] = base64_encode($certData);
        }

        $certData = null;
        openssl_x509_export($chain[0], $certData);
        $x5t = base64_encode(openssl_digest($certData, 'sha1', true));
        $x5t_s256 = base64_encode(openssl_digest($certData, 'sha256', true));

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'use' => 'sig',
                    'kid' => $keyId,
                    'n' => base64_encode(openssl_pkey_get_details($publicKey)['rsa']['n']),
                    'e' => 'AQAB',
                    'x5c' => $x5c,
                    'x5t' => $x5t,
                    'x5t#S256' => $x5t_s256,
                ],
            ],
        ];
    }
}
