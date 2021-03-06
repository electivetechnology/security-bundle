<?php

namespace Elective\SecurityBundle\Tests\Acl;

use Elective\SecurityBundle\Acl\Subject;
use PHPUnit\Framework\TestCase;

class SubjectTest extends TestCase
{
    protected function createSubject(): Subject
    {
        return new Subject();
    }

    public function nameProvider()
    {
        return [
            ['acme'],
            ['foo'],
            ['user']
        ];
    }

    /**
     * @dataProvider nameProvider
     */
    public function testSetGetNamePass($name)
    {
        $subject = $this->createSubject();

        $this->assertInstanceOf(Subject::class, $subject->setName($name));
        $this->assertEquals($name, $subject->getName());
    }

    public function subjectProvider()
    {
        return [
            ['acme'],
            [123],
            [new \StdClass()]
        ];
    }

    /**
     * @dataProvider subjectProvider
     */
    public function testSetGetSubjectPass($sub)
    {
        $subject = $this->createSubject();

        $this->assertInstanceOf(Subject::class, $subject->setSubject($sub));
        $this->assertEquals($sub, $subject->getSubject());
    }

    public function contextProvider()
    {
        return [
            ['acme'],
            ['acmeinc'],
        ];
    }

    /**
     * @dataProvider contextProvider
     */
    public function testSetGetContextPass($context)
    {
        $subject = $this->createSubject();

        $this->assertInstanceOf(Subject::class, $subject->setContext($context));
        $this->assertEquals($context, $subject->getContext());
    }
}
