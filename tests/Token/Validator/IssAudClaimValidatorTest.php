<?php

namespace Elective\SecurityBundle\Tests\Token\Validator;

use Elective\SecurityBundle\Token\Validator\IssAudClaimValidator;
use Elective\SecurityBundle\Token\Validator\ValidatorInterface;
use Elective\SecurityBundle\Exception\AuthenticationException;
use Elective\SecurityBundle\Exception\TokenDecoderException;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class IssAudClaimValidatorTest extends WebTestCase
{
    public function createValidator($aud = null, $iss = null): ValidatorInterface
    {
        $validator  = new IssAudClaimValidator($aud, $iss);

        return $validator;
    }

    public function setGetAudProvider()
    {
        return array(
            array('abc123'),
            array(1234),
        );
    }

    /**
     * @dataProvider setGetAudProvider
     */
    public function testSetGetAud($aud)
    {
        $validator = $this->createValidator();

        $this->assertInstanceOf(ValidatorInterface::class, $validator->setAud($aud));
        $this->assertEquals($aud, $validator->getAud());
    }

    public function setGetIssProvider()
    {
        return array(
            array('abc123'),
            array(1234),
            array(null)
        );
    }

    /**
     * @dataProvider setGetIssProvider
     */
    public function testSetGetIss($iss)
    {
        $validator = $this->createValidator();

        $this->assertInstanceOf(ValidatorInterface::class, $validator->setIss($iss));
        $this->assertEquals($iss, $validator->getIss());
    }

    public function validateProvider()
    {
        return array(
            array('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.1XOO35Ozn1XNEj_W7RFefNfJnVm7C1pm7MCEBPbCkJ4'),
        );
    }

    /**
     * @dataProvider validateProvider
     */
    public function testValidate($credentials = '')
    {
        $validator = $this->createValidator();

        $this->assertTrue(is_array($validator->validate($credentials)));
    }

    public function validateFailProvider()
    {
        return array(
            array(
                TokenDecoderException::TOKEN_DECODER_MISSING_CLAIM,
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.45O2fu-cjpRYWk7gf0BhPDVuIVoxic_xl6Dq8P18w_s',
                'abc'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_AUD,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiYXVkIjoiYWJjIn0.rXbgt21Om354m0Z6gHOaLfxVgLUQo_04YIGM53INUb0',
                'abcd'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.45O2fu-cjpRYWk7gf0BhPDVuIVoxic_xl6Dq8P18w_s',
                'abc',
                'abc'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_ISS,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiYXVkIjoiYWJjIiwiaXNzIjoiYWJjIn0.IKR6jeJMX-4BTCVYN_FbRbftKyCcr-nQxIpTIsUzwFI',
                'abc',
                'abcd'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiYXVkIjoiYWJjIn0.rXbgt21Om354m0Z6gHOaLfxVgLUQo_04YIGM53INUb0',
                'abc',
                'abc'
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN,
                'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiYXVkIjoiYWJjIiwiaXNzIjoiYWJjIiwiZXhwIjoxNTUwMTg1OTM1fQ.wgowN8guQU1m6jWYY7__xWHQL17IuTukptzwWspslVg',
            ),
            array(
                TokenDecoderException::TOKEN_DECODER_INVALID_TOKEN,
                'abc',
            ),
        );
    }

    /**
     * @dataProvider validateFailProvider
     */
    public function testValidateFail($code, $credentials = '', $aud = null, $iss = null)
    {
        $validator = $this->createValidator($aud, $iss);
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode($code);
        $validator->validate($credentials);
    }
}
