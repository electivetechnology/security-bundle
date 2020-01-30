<?php

namespace Elective\SecurityBundle\Token\Validator;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use \InvalidArgumentException;
use \OutOfBoundsException;

/**
 * Elective\SecurityBundle\Token\Validator\IssAudClaimValidator
 *
 * @author Kris Rybak <kris@elective.io>
 */
class IssAudClaimValidator implements ValidatorInterface
{
    /**
     * @var string|null
     */
    private $aud;

    /**
     * @var string|null
     */
    private $iss;

    public function __construct($aud = null, $iss = null) {
        $this->aud = $aud;
        $this->iss = $iss;
    }

    /**
     * Set Aud
     *
     * @param   string|null $aud  Audience
     * @return  ValidatorInterface
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
     * @return  ValidatorInterface
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
     * Validates token credentials
     *
     * @param string    $credentials    Credentials validate
     * @return array
     */
    public function validate(string $credentials): array
    {
        $token = array();

        // Let's try to verify self signed token
        // In this case we will need to verify Iss and Aud
        try {
            $apiToken = (new Parser())->parse((string) $credentials);
        } catch (InvalidArgumentException $e) {
            throw $e; 
        }

        // Check token claims are set
        if ($this->getAud()) {
            try {
                $aud = $apiToken->getClaim('aud');
                if ($aud != $this->getAud()) {
                    throw new AuthenticationException();
                }
            } catch (OutOfBoundsException $e) {
                throw new AuthenticationException();
            }
        }

        if ($this->getIss()) {
            try {
                $iss = $apiToken->getClaim('iss');
                if ($iss != $this->getIss()) {
                    throw new AuthenticationException();
                }
            } catch (OutOfBoundsException $e) {
                throw new AuthenticationException();
            }
        }

        // Validate apiToken
        $data = new ValidationData();
        $data->setIssuer($this->getIss());
        $data->setAudience($this->getAud());

        if (!$apiToken->validate($data)) {
            throw new AuthenticationException();
        }

        // Email claim is required for this type of token
        try {
            $apiToken->getClaim('email');
        } catch (OutOfBoundsException $e) {
            throw new AuthenticationException();
        }

        // Turn Token class into array and swap 'email' for 'username' property
        foreach ($apiToken->getClaims() as $claim) {
            ($claim->getName() == 'email') ? $key = 'username' : $key = $claim->getName();
            $token[$key] = $claim->getValue();
        }

        return $token;
    }
}
