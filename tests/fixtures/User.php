<?php

namespace Elective\SecurityBundle\Tests\fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Elective\SecurityBundle\Tests\fixtures\User
 *
 * @author Kris Rybak <kris@elective.io>
 */
class User implements UserInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * @var string
     */
    private $salt;

    /**
     * @var array
     */
    private $roles;

    public function __construct()
    {
        $this->roles = ['ROLE_USER'];
    }

    /**
     * Set roles
     *
     * @param   array $roles
     * @return  UserInterface
     */
    public function setRoles(array $roles): UserInterface
    {
        return $this;
    }

    /**
     * Get roles
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Set password
     *
     * @param   string $password
     * @return  UserInterface
     */
    public function setPassword(?string $password): UserInterface
    {
        return $this;
    }

    /**
     * Get password
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * Set salt
     *
     * @param   string $salt
     * @return  UserInterface
     */
    public function setSalt(?string $salt): UserInterface
    {
        return $this;
    }

    /**
     * Get salt
     */
    public function getSalt(): ?string
    {
        return $this->salt;
    }

    /**
     * Get username
     *
     * @return  string
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Set username
     *
     * @param   string $username
     * @return  UserInterface
     */
    public function setUsername(?string $username): UserInterface
    {
        return $this;
    }

    public function eraseCredentials()
    {
        return null;
    }
}
