<?php

namespace Elective\SecurityBundle\Token\Validator;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;

/**
 * Elective\SecurityBundle\Token\Validator\SignatureValidator
 *
 * @author Kris Rybak <kris@elective.io>
 */
class SignatureValidator implements ValidatorInterface
{
    /**
     * @var JWTEncoderInterface
     */
    private $encoder;

    public function __construct(JWTEncoderInterface $encoder) {
        $this->encoder = $encoder;
    }

    /**
     * Set encoder
     *
     * @param   JWTEncoderInterface|null    $encoder
     * @return  ValidatorInterface
     */
    public function setEncoder(?JWTEncoderInterface $encoder): self
    {
        $this->encoder = $encoder;

        return $this;
    }

    /**
     * Get encoder
     *
     * @return  JWTEncoderInterface|null
     */
    public function getEncoder(): ?JWTEncoderInterface
    {
        return $this->encoder;
    }

    /**
     * Validates token credentials
     *
     * @param string    $credentials    Credentials validate
     * @return array
     */
    public function validate(string $credentials): array
    {
        $token = array();

        // First let's try to validate token by verifying signature
        try {
            $token = $this->encoder->decode($credentials);
        } catch (JWTDecodeFailureException $e) {
            throw $e;
        }

        return $token;
    }
}
