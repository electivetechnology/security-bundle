<?php

namespace Elective\SecurityBundle\Tests\Provider;

use Elective\SecurityBundle\Entity\User;
use Elective\SecurityBundle\Provider\UserProvider;
use Elective\SecurityBundle\Tests\fixtures\User as TestUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use PHPUnit\Framework\TestCase;

class UserProviderTest extends TestCase
{
    protected function createProvider(): UserProvider
    {
        return new UserProvider();
    }

    public function testRefreshUser()
    {
        $user = $this->createMock(User::class);
        $provider = $this->createProvider();

        $this->assertSame($user, $provider->refreshUser($user));
        $this->assertInstanceOf(UserInterface::class, $provider->refreshUser($user));
    }

    public function testRefreshUserFail()
    {
        $this->expectException(UnsupportedUserException::class);
        $user = $this->createMock(TestUser::class);
        $provider = $this->createProvider();

        $this->assertSame($user, $provider->refreshUser($user));
        $this->assertInstanceOf(UserInterface::class, $provider->refreshUser($user));
    }

    public function testSupportsClass()
    {
        $user = new User();
        $provider = $this->createProvider();

        $this->assertTrue($provider->supportsClass(User::class));
        $this->assertTrue($provider->supportsClass(get_class($user)));
    }

    public function usernameProvider()
    {
        return array(
            ['abc'],
            ['jane.doe'],
        );
    }

    /**
     * @dataProvider usernameProvider
     */
    public function testLoadUserByUsername($username)
    {
        $provider = $this->createProvider();

        $this->assertInstanceOf(UserInterface::class, $user = $provider->loadUserByUsername($username));
        $this->assertEquals($user->getUsername(), $username);
    }
}
