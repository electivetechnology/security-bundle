<?php

namespace Elective\SecurityBundle\Token;

/**
 * Elective\SecurityBundle\Token\TokenKeyValidatorInterface
 *
 * @author Kris Rybak <kris@elective.io>
 */
interface TokenKeyValidatorInterface
{
    /**
     * Validates key
     *
     * @param string        $key                Key to validate
     * @param string|null   $serviceAccount     Service account for the key
     * @return boolean
     */
    public function validate(string $key, string $serviceAccount = null): bool;
}
