<?php

namespace Elective\SecurityBundle\Entity;

/**
 * Elective\SecurityBundle\Entity\ServiceAccountInterface
 *
 * @author Chris Dixon <chris@elective.io>
 */
interface ServiceAccountInterface
{
    public function decode(TokenInterface $token): array;

    public function getData(): ?array;

    public function getAttribute($attribute);
}
