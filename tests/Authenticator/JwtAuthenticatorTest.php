<?php

namespace Elective\SecurityBundle\Tests\Authenticator;

use Elective\SecurityBundle\Authenticator\JwtAuthenticator;
use Elective\SecurityBundle\Entity\User;
use Elective\SecurityBundle\Token\Validator\ValidatorInterface;
use Elective\SecurityBundle\Token\TokenKeyValidatorInterface;
use Elective\SecurityBundle\Exception\AuthenticationException as ElectiveAuthenticationException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\HeaderBag;
use Lcobucci\JWT\Builder;
use PHPUnit\Framework\TestCase;

class JwtAuthenticatorTest extends TestCase
{
    protected function createAuthenticator(): JwtAuthenticator
    {
        $authenticator = $this->createMock(ValidatorInterface::class);

        return new JwtAuthenticator($authenticator);
    }

    public function testSetGetValidator()
    {
        $authenticator = $this->createAuthenticator();
        $validator = $this->createMock(ValidatorInterface::class);

        $this->assertInstanceOf(JwtAuthenticator::class, $authenticator->setValidator($validator));
        $this->assertEquals($validator, $authenticator->getValidator());
    }

    public function testSetGetTokenKeyValidator()
    {
        $authenticator = $this->createAuthenticator();
        $keyValidator = $this->createMock(TokenKeyValidatorInterface::class);

        $this->assertInstanceOf(JwtAuthenticator::class, $authenticator->setTokenKeyValidator($keyValidator));
        $this->assertEquals($keyValidator, $authenticator->getTokenKeyValidator());
    }

    public function supportsDataProvider()
    {
        $request = new Request();
        $request->headers->set('authorization', 'Basic YWJjOmFjbWU=');

        return array(
            [$request, true],
            [new Request(), false],
        );
    }

    /**
     * @dataProvider supportsDataProvider
     */
    public function testSupports($request, $expected)
    {
        $authenticator = $this->createAuthenticator();

        $this->assertEquals($expected, $authenticator->supports($request));
    }

    public function getCredentialsProvider()
    {
        $token1 = 'abc';
        $token2 = 'abc123';
        $request1 = new Request();
        $request1->headers->set('authorization', 'Bearer ' . $token1);
        $request2 = new Request();
        $request2->headers->set('authorization',  'Bearer ' . $token2);
        $request3 = new Request();

        return array(
            [$request1, $token1],
            [$request2, $token2],
            [$request3, false],
        );
    }

    /**
     * @dataProvider getCredentialsProvider
     */
    public function testGetCredentials($request, $expected)
    {
        $authenticator = $this->createAuthenticator();

        $this->assertEquals($expected, $authenticator->getCredentials($request));
    }

    public function getUserProvider()
    {
        $time   = time();
        $email  = 'john.doe@example.com';

        return array(
            ['abc', null],
        );
    }

    /**
     * @dataProvider getUserProvider
     */
    public function testGetUser($credentials, $expected, $aud = null, $iss = null)
    {
        $authenticator = $this->createAuthenticator($aud, $iss);
        $provider = $this->createMock(UserProviderInterface::class);

        $this->assertEquals($expected, $authenticator->getUser($credentials, $provider));
    }

    public function getUserWithKeyProvider()
    {
        return array(
            array(['key' => 'abc', 'username' => 'john']),
            array(['key' => 'abc', 'username' => 'john'], 'john', true),
        );
    }

    /**
     * @dataProvider getUserWithKeyProvider
     */
    public function testGetUserWithKey($token = [], $expected = null, $keyValidatorResult = false, $credentials = '')
    {
        $authenticator = $this->createAuthenticator();
        $authenticator->getValidator()->method('validate')->willReturn($token);
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->method('loadUserByUsername')->willReturn($expected);
        $keyValidator = $this->createMock(TokenKeyValidatorInterface::class);
        $keyValidator->method('validate')->willReturn($keyValidatorResult);
        $authenticator->setTokenKeyValidator($keyValidator);

        $this->assertEquals($expected, $authenticator->getUser($credentials, $provider));
    }

    public function testCheckCredentials()
    {
        $authenticator = $this->createAuthenticator();
        $user = $this->createMock(User::class);

        $this->assertTrue($authenticator->checkCredentials('abc', $user));
    }

    public function testOnAuthenticationSuccess()
    {
        $authenticator  = $this->createAuthenticator();
        $request        = $this->createMock(Request::class);
        $heders         = $this->createMock(HeaderBag::class);
        $request->headers = $heders;
        $user           = $this->createMock(TokenInterface::class);

        $this->assertNull($authenticator->onAuthenticationSuccess($request, $user, 'providerKey'));
    }

    public function onAuthenticationFailureProvider()
    {
        return array(
            [Response::HTTP_FORBIDDEN, new AuthenticationException()],
            [Response::HTTP_UNAUTHORIZED, new ElectiveAuthenticationException()],
        );
    }

    /**
     * @dataProvider onAuthenticationFailureProvider
     */
    public function testOnAuthenticationFailure($code, $exception)
    {
        $authenticator  = $this->createAuthenticator();
        $request        = $this->createMock(Request::class);
        // $exception      = new AuthenticationException();

        $this->assertInstanceOf(Response::class, $response = $authenticator->onAuthenticationFailure($request, $exception));
        $this->assertEquals($code, $response->getStatusCode());
    }

    public function testStart()
    {
        $authenticator = $this->createAuthenticator();
        $request = $this->createMock(Request::class);

        $this->assertInstanceOf(Response::class, $response = $authenticator->start($request));
        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testSupportsRememberMe()
    {
        $authenticator = $this->createAuthenticator();

        $this->assertFalse($authenticator->supportsRememberMe());
    }
}
