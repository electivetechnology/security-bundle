<?php

namespace Elective\SecurityBundle\Tests\Entity;

use Elective\SecurityBundle\Entity\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class UserTest extends WebTestCase
{
    public function createUser(): UserInterface
    {
        return new User();
    }

    public function rolesProvider()
    {
        return array(
            [['USER_ROLE', 'OTHER_ROLE']],
            [['OTHER_ROLE']],
            [[]],
        );
    }

    /**
     * @dataProvider rolesProvider
     */
    public function testGetSetRoles($roles)
    {
        $user = $this->createUser();

        $this->assertTrue(is_array($user->getRoles()));
        $this->assertInstanceOf(UserInterface::class, $user->setRoles($roles));
        $this->assertEquals($roles, $user->getRoles());
    }

    public function usernameProvider()
    {
        return array(
            ['john.doe'],
            ['jane.doe.123'],
            [null],
        );
    }

    /**
     * @dataProvider usernameProvider
     */
    public function testGetSetUsername($username)
    {
        $user = $this->createUser();

        $this->assertInstanceOf(UserInterface::class, $user->setUsername($username));
        $this->assertEquals($username, $user->getUsername());
    }

    public function passwordProvider()
    {
        return array(
            ['abc123'],
            ['!987654320'],
            ['!987654320' . 0],
            [null],
        );
    }

    /**
     * @dataProvider passwordProvider
     */
    public function testGetSetPassword($password)
    {
        $user = $this->createUser();

        $this->assertInstanceOf(UserInterface::class, $user->setPassword($password));
        $this->assertEquals($password, $user->getPassword());
    }

    public function saltProvider()
    {
        return array(
            ['abc123Kld'],
            ['%£s!987654320'],
            ['!gshd7%fds987654320' . 0],
            [null],
        );
    }

    /**
     * @dataProvider saltProvider
     */
    public function testGetSetSalt($salt)
    {
        $user = $this->createUser();

        $this->assertInstanceOf(UserInterface::class, $user->setSalt($salt));
        $this->assertEquals($salt, $user->getSalt());
    }

    public function eraseCredentialsProvider()
    {
        return array(
            ['abc', '1234hxcba'],
        );
    }

    /**
     * @dataProvider eraseCredentialsProvider
     */
    public function testEraseCredentials($password, $salt)
    {
        $user = $this->createUser();
        $user->setSalt($salt)->setPassword($password);
        $user->eraseCredentials();
        $this->assertNull($user->getSalt());
        $this->assertNull($user->getPassword());
    }
}
