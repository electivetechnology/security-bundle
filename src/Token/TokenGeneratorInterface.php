<?php

namespace Elective\SecurityBundle\Token;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Elective\SecurityBundle\Token\TokenGeneratorInterface
 *
 * @author Kris Rybak <kris@elective.io>
 */
interface TokenGeneratorInterface
{
    /**
     * Generates token
     *
     * @param UserInterface
     * @param DateTimeInterface
     * @return string
     */
    public function generate(UserInterface $user, \DateTimeInterface $expiresAt = null, array $options = []): string;
}
