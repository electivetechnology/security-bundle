<?php

namespace Elective\SecurityBundle\Authenticator;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Elective\SecurityBundle\Token\TokenKeyValidatorInterface;
use Elective\SecurityBundle\Token\Validator\ValidatorInterface;
use Elective\SecurityBundle\Entity\User;

/**
 * Elective\SecurityBundle\Authenticator\JwtAuthenticator
 *
 * @author Kris Rybak <kris@elective.io>
 */
class JwtAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var TokenKeyValidatorInterface
     */
    private $tokenKeyValidator;

    public function __construct(
        ValidatorInterface $validator,
        TokenKeyValidatorInterface $tokenKeyValidator = null
    ) {
        $this->validator = $validator;
        $this->tokenKeyValidator = $tokenKeyValidator;
    }

    /**
     * Set validator
     *
     * @param   JWTEncoderInterface|null    $validator
     * @return  AbstractGuardAuthenticator
     */
    public function setValidator(?ValidatorInterface $validator): self
    {
        $this->validator = $validator;

        return $this;
    }

    /**
     * Get validator
     *
     * @return  ValidatorInterface|null
     */
    public function getValidator(): ?ValidatorInterface
    {
        return $this->validator;
    }

    /**
     * Get TokenKeyValidator
     *
     * @return TokenKeyValidatorInterface|null
     */
    public function getTokenKeyValidator(): ?TokenKeyValidatorInterface
    {
        return $this->tokenKeyValidator;
    }

    /**
     * Set TokenKeyValidator
     *
     * @param   TokenKeyValidatorInterface|null
     * @return  AbstractGuardAuthenticator
     */
    public function setTokenKeyValidator(?TokenKeyValidatorInterface $tokenKeyValidator): AbstractGuardAuthenticator
    {
        $this->tokenKeyValidator = $tokenKeyValidator;

        return $this;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        return $request->headers->has('authorization');
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

        if (!$token) {
            return false;
        }

        return $token;
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
        // Set initial state of Issuer and Audience
        $token  = [];

        // Validate the token
        $token = $this->getValidator()->validate($credentials);

        if (!isset($token['username'])) {
            return;
        }

        if (isset($token['key']) && !is_null($this->getTokenKeyValidator())) {
            if (!$this->getTokenKeyValidator()->validate($token['key'], $token['username'])) {
                return;
            }
        }

        $user = $userProvider->loadUserByUsername($token['username']);

        return $user;
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
        $token->rawToken = str_replace("Bearer ", "", $request->headers->get('authorization'));

        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
            'code' => Response::HTTP_FORBIDDEN

            // or to translate this message
            // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
        ];

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
