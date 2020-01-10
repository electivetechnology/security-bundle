<?php

namespace Elective\SecurityBundle\Token;

use Elective\SecurityBundle\Exception\TokenGeneratorException;
use Elective\SecurityBundle\Token\TokenGeneratorInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTEncodeFailureException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Elective\SecurityBundle\Token\JwtGenerator
 *
 * @author Kris Rybak <kris@elective.io>
 */
class JwtGenerator implements TokenGeneratorInterface
{
    /**
     * @var JWTEncoderInterface
     */
    private $encoder;

    public function __construct(JWTEncoderInterface $encoder)
    {
        $this->encoder = $encoder;
    }

    /**
     * Get encoder
     *
     * @return JWTEncoderInterface
     */
    public function getEncoder(): JWTEncoderInterface
    {
        return $this->encoder;
    }

    /**
     * Set encoder
     *
     * @param JWTEncoderInterface $encoder
     * @return JWTEncoderInterface
     */
    public function setEncoder(JWTEncoderInterface $encoder)
    {
        $this->encoder = $encoder;

        return $this;
    }

    public function generate(
        UserInterface $user,
        \DateTimeInterface $expiresAt = null,
        array $options = []
    ): string {
        // Token payload storage
        $payload = array();

        // Add username to payload
        $payload['username'] = $user->getUsername();

        // Add expiry date if needed, default JWT_TTL will be used if none provided
        if (!is_null($expiresAt)) {
            $payload['exp'] = $expiresAt->getTimestamp();
        }

        foreach ($options as $key => $value) {
            // Make sure you not going to override payload
            if (!isset($payload[$key])) {
                $payload[$key] = $value;
            }
        }

        try {
            $token = $this->getEncoder()->encode($payload);
        } catch (JWTEncodeFailureException $e) {
            throw new TokenGeneratorException($e->getReason(), 500);
        }

        return $token;
    }
}
