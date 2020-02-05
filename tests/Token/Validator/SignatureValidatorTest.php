<?php

namespace Elective\SecurityBundle\Tests\Token\Validator;

use Elective\SecurityBundle\Token\Validator\SignatureValidator;
use Elective\SecurityBundle\Token\Validator\ValidatorInterface;
use Elective\SecurityBundle\Exception\AuthenticationException;
use Elective\SecurityBundle\Exception\TokenDecoderException;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;

class SignatureValidatorTest extends WebTestCase
{
    public function createValidator(): ValidatorInterface
    {
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $validator  = new SignatureValidator($encoder);

        return $validator;
    }

    public function testSetGetEncoder()
    {
        $validator = $this->createValidator();

        $encoder = $this->createMock(JWTEncoderInterface::class);

        $this->assertInstanceOf(ValidatorInterface::class, $validator->setEncoder($encoder));
        $this->assertEquals($encoder, $validator->getEncoder());
    }

    public function testValidate($credentials = '')
    {
        $validator = $this->createValidator();
        $validator->getEncoder()->method('decode')->willReturn([]);

        $this->assertTrue(is_array($validator->validate($credentials)));
    }

    public function validateFailProvider()
    {
        $message = '';

        return array(
            array(
                new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, $message),
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN
            ),
            array(
                new JWTDecodeFailureException(JWTDecodeFailureException::EXPIRED_TOKEN, $message),
                TokenDecoderException::TOKEN_DECODER_EXPIRED_TOKEN
            ),
            array(
                new JWTDecodeFailureException(JWTDecodeFailureException::UNVERIFIED_TOKEN, $message),
                TokenDecoderException::TOKEN_DECODER_UNVERIFIED_TOKEN
            ),
            array(
                new JWTDecodeFailureException('default', $message),
                TokenDecoderException::TOKEN_DECODER_ERROR
            ),
        );
    }

    /**
     * @dataProvider validateFailProvider
     */
    public function testValidateFail($exception, $code, $credentials = '')
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode($code);
        $validator = $this->createValidator();
        $validator->getEncoder()->method('decode')->willThrowException($exception);
        $validator->validate($credentials);
    }
}
