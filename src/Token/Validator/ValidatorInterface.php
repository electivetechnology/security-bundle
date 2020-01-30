<?php

namespace Elective\SecurityBundle\Token\Validator;

/**
 * Elective\SecurityBundle\Token\Validator\ValidatorInterface
 *
 * @author Kris Rybak <kris@elective.io>
 */
interface ValidatorInterface
{
    /**
     * Validates token credentials
     *
     * @param string    $credentials    Credentials validate
     * @return array
     */
    public function validate(string $credentials): array;
}
