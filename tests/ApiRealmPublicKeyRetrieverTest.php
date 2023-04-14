<?php

namespace KeycloakAuthGuard\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use KeycloakAuthGuard\Services\ApiRealmPublicKeyRetriever;


class ApiRealmPublicKeyRetrieverTest extends TestCase
{
    public function test_receiving_of_public_key()
    {
        $retriever = new ApiRealmPublicKeyRetriever(
            $this->givenHttpClientWithSuccessfulResponse()
        );

        $this->assertEquals(
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mrGVPnxjLGmk0oh5dU9X4/b6X6xzvcM96GFC3OK0AVptvAsAH2HOPkGw0pO9VekC8yI0gT2PUvwRkTuqcnTfdeToXoo33/Z8P4Hvv2ssehvtIYoTmML3g3lkiPFrXZopU4MddPzkXa1522xr5XsXCFok3DGtWrzyMrYo5EaRg3vc4GVUiR1z6jbtBXM9bKEDeAy7gcXSMgGv+lMTT6wKCPLVkJ/5H8n8ihS2blqWdFxA7zbjArv2xR/4ZCgCoJSrKXGXUS8HnV6V90/e9qlzrfYPOtXxvOnuKDUL+1DL33IUcHQ0hPXK8bsquObBDub56EM8Or/1InRSUVcrQpF3wIDAQAB',
            $retriever->getPublicKey()
        );
    }

    private function givenHttpClientWithSuccessfulResponse(): ClientInterface
    {
        $mock = new MockHandler([
            new Response(200, [], '{"realm":"master","public_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mrGVPnxjLGmk0oh5dU9X4/b6X6xzvcM96GFC3OK0AVptvAsAH2HOPkGw0pO9VekC8yI0gT2PUvwRkTuqcnTfdeToXoo33/Z8P4Hvv2ssehvtIYoTmML3g3lkiPFrXZopU4MddPzkXa1522xr5XsXCFok3DGtWrzyMrYo5EaRg3vc4GVUiR1z6jbtBXM9bKEDeAy7gcXSMgGv+lMTT6wKCPLVkJ/5H8n8ihS2blqWdFxA7zbjArv2xR/4ZCgCoJSrKXGXUS8HnV6V90/e9qlzrfYPOtXxvOnuKDUL+1DL33IUcHQ0hPXK8bsquObBDub56EM8Or/1InRSUVcrQpF3wIDAQAB","token-service":"http://localhost:8080/realms/master/protocol/openid-connect","account-service":"http://localhost:8080/realms/master/account","tokens-not-before":0}'),
        ]);

        $handlerStack = HandlerStack::create($mock);
        return new Client(['handler' => $handlerStack]);
    }
}