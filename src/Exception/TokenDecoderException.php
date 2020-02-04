<?php

namespace Elective\SecurityBundle\Exception;

/**
 * Elective\SecurityBundle\Exception\TokenDecoderException
 *
 * @author Kris Rybak <kris@elective.io>
 */
class TokenDecoderException extends \Exception
{
    public const TOKEN_DECODER_ERROR            = 500180102;
    public const TOKEN_DECODER_INVALID_TOKEN    = 401180001;
    public const TOKEN_DECODER_EXPIRED_TOKEN    = 401180002;
    public const TOKEN_DECODER_UNVERIFIED_TOKEN = 401180003;
}
