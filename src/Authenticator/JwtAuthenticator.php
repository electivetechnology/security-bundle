<?php

namespace Elective\SecurityBundle\Authenticator;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Elective\SecurityBundle\Entity\User;
use \InvalidArgumentException;
use \OutOfBoundsException;

/**
 * Elective\SecurityBundle\Authenticator\JwtAuthenticator
 *
 * @author Kris Rybak <kris@elective.io>
 */
class JwtAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var string|null
     */
    private $aud;

    /**
     * @var string|null
     */
    private $iss;

    public function __construct($aud = null, $iss = null)
    {
        $this->aud = $aud;
        $this->iss = $iss;
    }

    /**
     * Set Aud
     *
     * @param   string|null $aud  Audience
     * @return  AbstractGuardAuthenticator
     */
    public function setAud(?string $aud): self
    {
        $this->aud = $aud;

        return $this;
    }

    /**
     * Get Aud
     *
     * @return  string|null     Audience
     */
    public function getAud(): ?string
    {
        return $this->aud;
    }

    /**
     * Set Iss
     *
     * @param   string|null $iss  Issuer
     * @return  AbstractGuardAuthenticator
     */
    public function setIss(?string $iss): self
    {
        $this->iss = $iss;

        return $this;
    }

    /**
     * Get Iss
     *
     * @return  string|null     Issuer
     */
    public function getIss(): ?string
    {
        return $this->iss;
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
        return [
            'token' => $request->headers->get('authorization'),
        ];
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
        if (!is_array($credentials) || !isset($credentials['token'])) {
            return;
        }

        $token = $credentials['token'];

        // Only supports Bearer Tokens at the moment
        if (!stristr($token, 'Bearer')) {
            return;
        }

        $bearerToken = str_replace('Bearer ', '', $token);

        try {
            $apiToken = (new Parser())->parse((string) $bearerToken);
        } catch (InvalidArgumentException $e) {
            return;
        }

        // Validate apiToken
        $data = new ValidationData();
        $data->setIssuer($this->getIss());
        $data->setAudience($this->getAud());

        // Check token claims are set
        if ($this->getAud()) {
            try {
                $aud = $apiToken->getClaim('aud');
                if ($aud != $this->getAud()) {
                    return;
                }
            } catch (OutOfBoundsException $e) {
                return;
            }
        }

        if ($this->getIss()) {
            try {
                $iss = $apiToken->getClaim('iss');
                if ($iss != $this->getIss()) {
                    return;
                }
            } catch (OutOfBoundsException $e) {
                return;
            }
        }

        try {
            $email = $apiToken->getClaim('email');
        } catch (OutOfBoundsException $e) {
            return;
        }

        if (!$apiToken->validate($data)) {
            return;
        }

        $user = new User();
        $user
            ->setUsername($apiToken->getClaim('email'));

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
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())

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
            'message' => 'Authentication Required'
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
