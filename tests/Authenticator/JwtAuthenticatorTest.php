<?php

namespace Elective\SecurityBundle\Tests\Authenticator;

use Elective\SecurityBundle\Authenticator\JwtAuthenticator;
use Elective\SecurityBundle\Entity\User;
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
    protected function createAuthenticator($aud = null, $iss = null): JwtAuthenticator
    {
        return new JwtAuthenticator($aud, $iss);
    }

    public function issProvider()
    {
        return array(
            ['https://accounts.google.com'],
            ['https://recii.io'],
            [null],
        );
    }

    /**
     * @dataProvider issProvider
     */
    public function testGetSetIss($iss)
    {
        $authenticator = $this->createAuthenticator();

        $this->assertInstanceOf(JwtAuthenticator::class, $authenticator->setIss($iss));
        $this->assertEquals($iss, $authenticator->getIss());
    }

    public function audProvider()
    {
        return array(
            ['KlsmH6kGfhQOwuRy4jr6'],
            ['Tt284abc'],
            [null],
        );
    }

    /**
     * @dataProvider audProvider
     */
    public function testGetSetAud($aud)
    {
        $authenticator = $this->createAuthenticator();

        $this->assertInstanceOf(JwtAuthenticator::class, $authenticator->setAud($aud));
        $this->assertEquals($aud, $authenticator->getAud());
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
        $request1->headers->set('authorization', $token1);
        $request2 = new Request();
        $request2->headers->set('authorization', $token2);

        return array(
            [$request1, ['token' => $token1]],
            [$request2, ['token' => $token2]],
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
            [['foo' => 'bar'], null],
            [['token' => 'bar'], null],
            [['token' => 'Bearer abc'], null],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time - 3600)->getToken()], null],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->getToken()], null, 'www.example.com'],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->permittedFor('www.example.net')->getToken()], null, 'www.example.com'],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->getToken()], null, null, 'acme'],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->issuedBy('acme')->getToken()], null, null, 'not_acme'],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->getToken()], null],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time + 3600)->withClaim('email', $email)->getToken()], (new User())->setUsername($email)],
            [['token' => 'Bearer ' . (new Builder())->issuedAt($time)->expiresAt($time - 3600)->withClaim('email', $email)->getToken()], null],
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

    public function testOnAuthenticationFailure()
    {
        $authenticator  = $this->createAuthenticator();
        $request        = $this->createMock(Request::class);
        $exception      = new AuthenticationException();

        $this->assertInstanceOf(Response::class, $response = $authenticator->onAuthenticationFailure($request, $exception));
        $this->assertEquals(Response::HTTP_FORBIDDEN, $response->getStatusCode());
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
