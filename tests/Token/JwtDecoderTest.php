<?php

namespace Elective\SecurityBundle\Tests\Token;

use Elective\SecurityBundle\Token\JwtDecoder;
use Elective\SecurityBundle\Token\TokenDecoderInterface;
use Elective\SecurityBundle\Exception\TokenDecoderException;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Lcobucci\JWT\Parser;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Guard\Token\GuardTokenInterface;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;

class JwtDecoderTest extends WebTestCase
{
    public function createJwtTokenDecoder(): JwtDecoder
    {
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $storage    = $this->createMock(TokenStorageInterface::class);
        $parser     = $this->createMock(Parser::class);
        $token      = $this->createMock(TokenInterface::class);

        $storage->method('getToken')->willReturn($token);
        $decoder    = new JwtDecoder($encoder, $storage, $parser);

        return $decoder;
    }

    public function testGetSetEncoder()
    {
        $decoder = $this->createJwtTokenDecoder();
        $encoder = $this->createMock(JWTEncoderInterface::class);

        $this->assertInstanceOf(TokenDecoderInterface::class, $decoder->setEncoder($encoder));
        $this->assertEquals($encoder, $decoder->getEncoder());
    }

    public function testGetSetParser()
    {
        $decoder = $this->createJwtTokenDecoder();
        $parser = $this->createMock(Parser::class);

        $this->assertInstanceOf(TokenDecoderInterface::class, $decoder->setParser($parser));
        $this->assertEquals($parser, $decoder->getParser());
    }

    public function testGetSetTokenStorage()
    {
        $decoder = $this->createJwtTokenDecoder();
        $tokenStorage = $this->createMock(TokenStorageInterface::class);

        $this->assertInstanceOf(TokenDecoderInterface::class, $decoder->setTokenStorage($tokenStorage));
        $this->assertEquals($tokenStorage, $decoder->getTokenStorage());
    }

    public function getSetDataProvider()
    {
        return array(
            array([]),
            array(['foo', 'bar']),
        );
    }

    /**
     * @dataProvider getSetDataProvider
     */
    public function testGetSetData($data)
    {
        $decoder = $this->createJwtTokenDecoder();

        $this->assertInstanceOf(TokenDecoderInterface::class, $decoder->setData($data));
        $this->assertEquals($data, $decoder->getData());
    }

    public function tokenProvider()
    {
        $jwtToken = $this
                    ->getMockBuilder(PostAuthenticationGuardToken::class)
                    ->disableOriginalConstructor()
                    ->getMock();

        $jwtToken->rawToken = 'a';

        $guardToken = $this->createMock(JWTUserToken::class);
        $guardToken->method('getCredentials')->willReturn('abc');

        return array(
            array($jwtToken),
            array($guardToken),
        );
    }

    /**
     * @dataProvider tokenProvider
     */
    public function testDecode($token)
    {
        $decoder = $this->createJwtTokenDecoder();

        $decoded = $this
            ->getMockBuilder(\StdClass::class)
            ->setMethods(['getClaims'])
            ->getMock();
        $decoded->method('getClaims')->willReturn([]);

        $decoder->getEncoder()->method('decode')->willReturn([]);
        $decoder->getParser()->method('parse')->willReturn($decoded);

        $this->assertTrue(is_array($decoder->decode($token)));
    }

    public function getAttributeProvider()
    {
        $data = array(
            'foo' => 'bar',
            'moo' => 'loo',
        );

        return array(
            array($data, 'foo', 'bar'),
            array($data, 'moo', 'loo'),
            array($data, 'none', null),
        );
    }

    /**
     * @dataProvider getAttributeProvider
     */
    public function testGetAttribute($data, $attribute, $value)
    {
        $decoder = $this->createJwtTokenDecoder();
        $decoder->setData($data);
        $this->assertEquals($value, $decoder->getAttribute($attribute));
    }

    public function testDecodeJWTUserToken()
    {
        $decoder = $this->createJwtTokenDecoder();
        $this->assertTrue(is_array($decoder->decodeJWTUserToken([])));
    }

    public function testDecodeGuardToken()
    {
        $decoder = $this->createJwtTokenDecoder();
        $this->assertTrue(is_array($decoder->decodeGuardToken([])));
    }

    public function testDecodeJWTUserTokenFail()
    {
        $this->expectException(TokenDecoderException::class);
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $storage    = $this->createMock(TokenStorageInterface::class);
        $token      = $this->createMock(TokenInterface::class);
        $storage->method('getToken')->willReturn($token);
        $exception  = $this->createMock(JWTDecodeFailureException::class);

        $encoder->method('decode')->willThrowException($exception);
        $decoder    = new JwtDecoder($encoder, $storage);

        $this->assertTrue(is_array($decoder->decodeJWTUserToken('abc')));
    }

    public function testDecodeGuardTokenFail()
    {
        $this->expectException(TokenDecoderException::class);
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $storage    = $this->createMock(TokenStorageInterface::class);
        $token      = $this->createMock(TokenInterface::class);
        $storage->method('getToken')->willReturn($token);
        $exception  = $this->createMock(\InvalidArgumentException::class);

        $encoder->method('decode')->willThrowException($exception);
        $decoder    = new JwtDecoder($encoder, $storage);

        $this->assertTrue(is_array($decoder->decodeGuardToken('abc')));
    }
}
