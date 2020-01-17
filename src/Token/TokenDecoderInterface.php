<?php

namespace Elective\SecurityBundle\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Elective\SecurityBundle\Token\TokenDecoderInterface
 *
 * @author Kris Rybak <kris@elective.io>
 */
interface TokenDecoderInterface
{
    public function decode(TokenInterface $token): array;

    public function getData(): ?array;

    public function getAttribute($attribute);
}
