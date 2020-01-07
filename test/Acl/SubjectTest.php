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
        return array(
            'acme',
            'foo',
            'user'
        );
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
}
