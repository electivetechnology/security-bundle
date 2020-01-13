<?php

namespace Elective\SecurityBundle\Token;

use Elective\SecurityBundle\Exception\TokenDecoderException;
use Elective\SecurityBundle\Token\TokenDecoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Elective\SecurityBundle\Token\JwtDecoder
 *
 * @author Kris Rybak <kris@elective.io>
 */
class JwtDecoder implements TokenDecoderInterface
{
    /**
     * @var JWTEncoderInterface
     */
    private $encoder;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array
     */
    private $data;

    public function __construct(JWTEncoderInterface $encoder, TokenStorageInterface $tokenStorage)
    {
        $this->encoder      = $encoder;
        $this->tokenStorage = $tokenStorage;
        $this->data         = $this->decode($tokenStorage->getToken()->getCredentials());
    }

    /**
     * Get encoder
     *
     * @return JWTEncoderInterface
     */
    public function getEncoder(): ?JWTEncoderInterface
    {
        return $this->encoder;
    }

    /**
     * Set encoder
     *
     * @param   JWTEncoderInterface $encoder
     * @return  TokenDecoderInterface
     */
    public function setEncoder(?JWTEncoderInterface $encoder): self
    {
        $this->encoder = $encoder;

        return $this;
    }

    /**
     * Get tokenStorage
     *
     * @return TokenStorageInterface
     */
    public function getTokenStorage(): ?TokenStorageInterface
    {
        return $this->tokenStorage;
    }

    /**
     * Set tokenStorage
     *
     * @param   TokenStorageInterface $tokenStorage
     * @return  TokenDecoderInterface
     */
    public function setTokenStorage(?TokenStorageInterface $tokenStorage): self
    {
        $this->tokenStorage = $tokenStorage;

        return $this;
    }

    /**
     * Get data
     *
     * @return array
     */
    public function getData(): ?array
    {
        return $this->data;
    }

    /**
     * Set data
     *
     * @param   array   $data
     * @return  TokenDecoderInterface
     */
    public function setData(?array $data): self
    {
        $this->data = $data;

        return $this;
    }

    /**
     * Decodes token
     *
     * @param   string      $credentials
     * @return  array       Array of decoded Token payload
     */
    public function decode($credentials): array
    {
        $data = array();

        try {
            $decoded = $this->encoder->decode($credentials);
            $data = !is_null($decoded) ? $decoded : [];
        } catch (JWTDecodeFailureException $e) {
            throw new TokenDecoderException('Could not decode token data');
        }

        $this->data = $data;

        return $data;
    }

    /**
     * Returns one of the data attributes
     *
     * @param   string  $attribute
     * @return  string|null     Attribute value if exists, otherwise null
     */
    public function getAttribute($attribute)
    {
        if (isset($this->data[$attribute])) {
            return $this->data[$attribute];
        }

        return null;
    }
}
