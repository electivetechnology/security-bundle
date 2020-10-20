# electivetechnology/security-bundle

[![Build Status](https://travis-ci.org/electivetechnology/security-bundle.svg?branch=master)](https://travis-ci.org/electivetechnology/security-bundle)

Provides collection of utility classes for handling authentication/autorisation processes.
This project is compatible with following Symfony versions:

* 3.x
* 4.x
* 5.x

## Requirements

* PHP 7.1 and up

## Installation

Make sure Composer is installed globally, as explained in the
[installation chapter](https://getcomposer.org/doc/00-intro.md)
of the Composer documentation.

Applications that use Symfony Flex
----------------------------------

Open a command console, enter your project directory and execute:

```console
$ composer require electivetechnology/security-bundle
```

Applications that don't use Symfony Flex
----------------------------------------

### Step 1: Download the Bundle

Open a command console, enter your project directory and execute the
following command to download the latest stable version of this bundle:

```console
$ composer require electivetechnology/security-bundle
```

### Step 2: Enable the Bundle

Then, enable the bundle by adding it to the list of registered bundles
in the `config/bundles.php` file of your project:

```php
// config/bundles.php

return [
    // ...
    Elective\SecurityBundle\ElectiveSecurityBundle::class => ['all' => true],
];
```
