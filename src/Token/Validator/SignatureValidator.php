<?php

namespace Elective\SecurityBundle\Token\Validator;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Elective\SecurityBundle\Exception\TokenDecoderException;
use Elective\SecurityBundle\Exception\AuthenticationException;

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
            switch ($e->getReason()) {
                case JWTDecodeFailureException::INVALID_TOKEN:
                    $message = $e->getMessage();
                    $code = TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN;
                    break;
                
                case JWTDecodeFailureException::EXPIRED_TOKEN:
                    $message = $e->getMessage();
                    $code = TokenDecoderException::TOKEN_DECODER_EXPIRED_TOKEN;
                    break;

                case JWTDecodeFailureException::UNVERIFIED_TOKEN:
                    $message = $e->getMessage();
                    $code = TokenDecoderException::TOKEN_DECODER_UNVERIFIED_TOKEN;
                    break;

                default:
                    $message = $e->getMessage();
                    $code = TokenDecoderException::TOKEN_DECODER_ERROR;
                    break;
            }

            throw new AuthenticationException($message, $code);
        }

        return $token;
    }
}
