<?php

namespace Elective\SecurityBundle\Tests\Token;

use Elective\SecurityBundle\Token\JwtDecoder;
use Elective\SecurityBundle\Token\TokenDecoderInterface;
use Elective\SecurityBundle\Exception\TokenDecoderException;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class JwtDecoderTest extends WebTestCase
{
    public function createJwtTokenDecoder(): JwtDecoder
    {
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $storage    = $this->createMock(TokenStorageInterface::class);
        $token      = $this->createMock(TokenInterface::class);

        $storage->method('getToken')->willReturn($token);
        $decoder    = new JwtDecoder($encoder, $storage);

        return $decoder;
    }

    public function testGetSetEncoder()
    {
        $decoder = $this->createJwtTokenDecoder();
        $encoder = $this->createMock(JWTEncoderInterface::class);

        $this->assertInstanceOf(TokenDecoderInterface::class, $decoder->setEncoder($encoder));
        $this->assertEquals($encoder, $decoder->getEncoder());
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

    public function credentialsProvider()
    {
        return array(
            array('abc'),
        );
    }

    /**
     * @dataProvider credentialsProvider
     */
    public function testDecode($credentials)
    {
        $this->expectException(TokenDecoderException::class);
        $exception = $this->createMock(JWTDecodeFailureException::class);
        $decoder = $this->createJwtTokenDecoder();
        $decoder->getEncoder()->method('decode')->willThrowException($exception);

        $decoder->decode($credentials);
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
}
