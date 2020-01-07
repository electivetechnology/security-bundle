<?php

namespace Elective\SecurityBundle\Acl;

/**
 * Elective\SecurityBundle\Acl
 *
 * @author Kris Rybak <kris@elective.io>
 */
class Subject
{
    /**
     * Name of the Subject, etc "User"
     *
     * @var str
     */
    private $name;

    /**
     * Object or object Id
     *
     * @var str|Object
     */
    private $subject;

    /**
     * Organisation object or organisation namespace
     *
     * @var str
     */
    private $context;

    public function __construct($name = null, $subject = null, $context = null)
    {
        $this->setName($name);
        $this->setSubject($subject);
        $this->setContext($context);
    }

    /**
     * Set name
     *
     * @return  Subject
     */
    public function setName($name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * Set subject
     *
     * @return  Subject
     */
    public function setSubject($subject): self
    {
        $this->subject = $subject;

        return $this;
    }

    /**
     * Get subject
     */
    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * Set context
     *
     * @param   str|Object      $context    Organisation object or namespace
     * @return  Subject
     */
    public function setContext($context): self
    {
        $this->context = $context;

        return $this;
    }

    /**
     * Get context
     */
    public function getContext()
    {
        return $this->context;
    }
}
