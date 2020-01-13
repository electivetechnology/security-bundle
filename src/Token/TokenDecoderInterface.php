<?php

namespace Elective\SecurityBundle\Token;

/**
 * Elective\SecurityBundle\Token\TokenDecoderInterface
 *
 * @author Kris Rybak <kris@elective.io>
 */
interface TokenDecoderInterface
{
    public function decode($credentials): array;

    public function getData(): ?array;

    public function getAttribute($attribute);
}
