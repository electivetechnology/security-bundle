<?php

namespace Elective\SecurityBundle\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;

/**
 * Elective\SecurityBundle\Handler\AccessDeniedHandler
 *
 * @author Kris Rybak <kris@elective.io>
 */
class AccessDeniedHandler implements AccessDeniedHandlerInterface
{
    public const ACCESS_DENIED_ERROR = 403180001;

    public function handle(Request $request, AccessDeniedException $accessDeniedException)
    {
        $ret = new \StdClass();
        $ret->message   = 'Access denied';
        $ret->code      = self::ACCESS_DENIED_ERROR;

        $headers = [
            'Access-Control-Allow-Origin' => '*'
        ];

        return new JsonResponse($ret, JsonResponse::HTTP_FORBIDDEN, $headers);
    }
}
