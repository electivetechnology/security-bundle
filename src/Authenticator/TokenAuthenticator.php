<?php

namespace Elective\SecurityBundle\Authenticator;

use Elective\SecurityBundle\Entity\ServiceAccountInterface;
use Elective\SecurityBundle\Token\Validator\ValidatorInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Elective\SecurityBundle\Exception\AuthenticationException as ElectiveAuthenticationException;

/**
 * Elective\SecurityBundle\Authenticator\TokenAuthenticator
 *
 * @author Chris Dixon <chris@elective.io>
 */
class TokenAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var ServiceAccountInterface
     */
    private $serviceAccount;

    public function __construct(
        ServiceAccountInterface $serviceAccount
    ) {
        $this->setServiceAccount($serviceAccount);
    }

    public function setServiceAccount(?ServiceAccountInterface $serviceAccount): self
    {
        $this->serviceAccount = $serviceAccount;

        return $this;
    }

    public function getServiceAccount(): ?ServiceAccountInterface
    {
        return $this->serviceAccount;
    }
    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        return ($request->headers->has('authorization') ||  $request->query->get('token'));
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        $extractor = new AuthorizationHeaderTokenExtractor(
            'Bearer',
            'Authorization'
        );

        $token = $extractor->extract($request);

        if ($token) {
            return $token;
        }

        if ($request->query->get('token')) {
            return $request->query->get('token');
        }

        return false;
    }

    /**
     * Get User
     *
     * @param   mixed $credentials
     * @param   UserProviderInterface
     * @return  UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $serviceAccount = $this->serviceAccount
            ->findOneByValidToken($credentials);

        if ($serviceAccount && $serviceAccount->getUser()) {
            return $serviceAccount->getUser();
        }
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        // check credentials - e.g. make sure the password is valid
        // no credential check is needed in this case

        // return true to cause authentication success
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($exception instanceof ElectiveAuthenticationException) {
            $data = [
                'message' => $exception->getMessage(),
                'code' => $exception->getCode()
            ];

            return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
        } else {
            $data = [
                'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
                'code' => Response::HTTP_FORBIDDEN
            ];
        }

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            // you might translate this message
            'message' => 'Authentication Required',
            'code' => Response::HTTP_UNAUTHORIZED
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
