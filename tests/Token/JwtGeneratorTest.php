<?php

namespace Elective\SecurityBundle\Tests\Token;

use Elective\SecurityBundle\Token\JwtGenerator;
use Elective\SecurityBundle\Exception\TokenGeneratorException;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTEncodeFailureException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class JwtGeneratorTest extends WebTestCase
{
    private $jwtTtl;

    public function setUp(): void
    {
        $this->jwtTtl = getenv('JWT_TTL');
    }

    public function createJwtTokenGenerator(): JwtGenerator
    {
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $generator  = new JwtGenerator($encoder);

        return $generator;
    }

    public function generateDataProvider()
    {
        $user = $this->createMock(UserInterface::class);

        return array(
            array($user),
            array($user, new \DateTime('+10 min')),
            array($user, new \DateTime('20-03-2025')),
            array($user, new \DateTime('20-03-2025'), array('foo' => 'bar')),
        );
    }

    /**
     * @dataProvider generateDataProvider
     */
    public function testGenerate($user, $expiresAt = null, $options = [])
    {
        $token = json_encode($options);
        $generator = $this->createJwtTokenGenerator();
        $generator->getEncoder()->method('encode')->willReturn(json_encode($token));
        $token = $generator->generate($user, $expiresAt, $options);
        $this->assertTrue(is_string($token));
        $this->assertTrue(is_string($token));
    }

    /**
     * @dataProvider generateDataProvider
     */
    public function testGenerateSetEncoder($user, $expiresAt = null, $options = [])
    {
        $token      = json_encode($options);
        $generator  = $this->createJwtTokenGenerator();
        $encoder    = $this->createMock(JWTEncoderInterface::class);
        $generator->setEncoder($encoder);
        $generator->getEncoder()->method('encode')->willReturn(json_encode($token));
        $token = $generator->generate($user, $expiresAt, $options);
        $this->assertTrue(is_string($token));
    }

    /**
     * @dataProvider generateDataProvider
     */
    public function testGenerateFail($user, $expiresAt = null, $options = [])
    {
        $this->expectException(TokenGeneratorException::class);
        $token = json_encode($options);
        $exception = $this->createMock(JWTEncodeFailureException::class);
        $generator = $this->createJwtTokenGenerator();
        $generator->getEncoder()->method('encode')->willThrowException($exception);
        $token = $generator->generate($user, $expiresAt, $options);
    }
}
