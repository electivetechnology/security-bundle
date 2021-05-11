<?php

namespace Elective\SecurityBundle\Entity;

/**
 * Elective\SecurityBundle\Entity\ServiceAccountInterface
 *
 * @author Chris Dixon <chris@elective.io>
 */
interface ServiceAccountInterface
{
    public function findOneByValidToken(string $token);
}
