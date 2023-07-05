<?php

namespace KeycloakAuthGuard\Tests;

use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use KeycloakAuthGuard\Services\ServiceAccountJwtRetriever;

class ServiceAccountJwtRetrieverTest extends TestCase
{
    /**
     * @throws RequestException
     */
    public function test_receiving_of_service_account_jwt()
    {
        Http::fake(fn () => Http::response($this->responseWithJwt()));
        $jwt = (new ServiceAccountJwtRetriever('', ''))->getJwt();
        $this->assertEquals($this->responseWithJwt()['access_token'], $jwt);
    }

    private function responseWithJwt(): array
    {
        return [
            'access_token' => 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjc2ZMMllPbFhLVWRiR18yV1AwVjQwX21Uc1VCUjdpN1pKRU1pa2hUdnNFIn0.eyJleHAiOjE2ODU0NDQyMDUsImlhdCI6MTY4NTQ0MzkwNSwianRpIjoiOWZiZjhjMjMtOWVhMC00MTIxLWE5NGMtNzA2ZGZiYmExNWRkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90b2xrZXZhcmF2LWRldiIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIxZTIyMDdiMy1jZWY0LTQyOTQtOTg4NC0yZjE1NDk4YzJiNzIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJkZW1vYXBwIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJkZWZhdWx0LXJvbGVzLXRvbGtldmFyYXYtZGV2IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudEhvc3QiOiIxNzIuMTcuMC4xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LWRlbW9hcHAiLCJjbGllbnRBZGRyZXNzIjoiMTcyLjE3LjAuMSIsImNsaWVudF9pZCI6ImRlbW9hcHAifQ.PccmNCJ_6xKFtqfIdzEARi83LAhu2HlF7MuwnDrb8xK9R-lkc5rW3bwZh1vyp9kmMM76BumMiiOO5dT6_ENk6Cabc4iXbg4Dn58URU5ZEEidE-a28vLB5GhXBQRidEvMKyfd8dAaOC1XTlXgmVvTObswoL1faMz07VTQVaZvdLR2xZiCDk_GYo0PWH4bsRsZGoR7_a1RyudRS0pL-6sSwhBcIgSMociFu2edrHRIfrRtgvcHYvWuk5ZhSgwcSLbZY_U4k7aoVTx8jT3iuciO_2BzJnLxeGtP_fONynHygVEeWyFjvugyzlGU6zkge16D-1jBktt4xb-GLMwKy_9YjQ',
            'expires_in' => 300,
        ];
    }
}
