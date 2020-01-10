<?php

namespace Elective\SecurityBundle\Tests\Acl;

use Elective\SecurityBundle\Handler\AccessDeniedHandler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use PHPUnit\Framework\TestCase;

class AccessDeniedHandlerTest extends TestCase
{
    protected function createHandler(): AccessDeniedHandler
    {
        return new AccessDeniedHandler();
    }

    public function handlePassProvider()
    {
        return array(
            array($this->createMock(Request::class), $this->createMock(AccessDeniedException::class)),
        );
    }

    /**
     * @dataProvider handlePassProvider
     */
    public function testHandlePass($request, $accessDeniedException)
    {
        $handler = $this->createHandler();
        $this->assertInstanceOf(JsonResponse::class, $response = $handler->handle($request, $accessDeniedException));
        $this->assertEquals($response->getStatusCode(), JsonResponse::HTTP_FORBIDDEN);
        // Get content
        $ret = json_decode($response->getContent());
        $this->assertTrue(isset($ret->message));
        $this->assertTrue(isset($ret->code));
    }
}
