<?php

namespace Elective\SecurityBundle\Token;

use Elective\SecurityBundle\Exception\TokenDecoderException;
use Elective\SecurityBundle\Token\TokenDecoderInterface;
use Lcobucci\JWT\Parser;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;
use \InvalidArgumentException;

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
     * @var Parser
     */
    private $parser;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array
     */
    private $data = [];

    public function __construct(JWTEncoderInterface $encoder, TokenStorageInterface $tokenStorage, $parser = null)
    {
        if (!$parser) {
            $parser = new Parser();
        }

        $this->encoder      = $encoder;
        $this->tokenStorage = $tokenStorage;
        $this->parser       = $parser;        

        $this->data = $this->decode($tokenStorage->getToken());
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
     * Get parser
     *
     * @return Parser
     */
    public function getParser(): ?Parser
    {
        return $this->parser;
    }

    /**
     * Set parser
     *
     * @param   Parser $parser
     * @return  TokenDecoderInterface
     */
    public function setParser(?Parser $parser): self
    {
        $this->parser = $parser;

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
    public function decode(TokenInterface $token): array
    {
        $data = array();

        if (is_a($token, PostAuthenticationGuardToken::class) && isset($token->rawToken)) {
            $credentials = $token->rawToken;
            $data = $this->decodeGuardToken($credentials);
        } elseif (is_a($token, JWTUserToken::class)) {
            $credentials = $token->getCredentials();
            $data = $this->decodeJWTUserToken($credentials);
        }

        $this->data = $data;

        return $data;
    }
    public function decodeGuardToken($credentials): array
    {
        if (empty($credentials)) {
            return [];
        }

        try {
            $decoded = $this->getParser()->parse($credentials);
            $data = !is_null($decoded->getClaims()) ? $decoded->getClaims() : [];
        } catch (InvalidArgumentException $e) {
            throw new TokenDecoderException('Could not decode token data');
        }

        return $data;
    }

    public function decodeJWTUserToken($credentials): array
    {
        if (empty($credentials)) {
            return [];
        }

        try {
            $decoded = $this->getEncoder()->decode($credentials);
            $data = !is_null($decoded) ? $decoded : [];
        } catch (JWTDecodeFailureException $e) {
            throw new TokenDecoderException('Could not decode token data');
        }

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
