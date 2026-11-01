<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

/**
 * The library was set up wrongly: a missing environment id, a publishable
 * key where a secret key belongs. Raised at construction, so it shows up
 * when the app boots rather than on the first real request.
 */
final class ConfigurationException extends ZevAuthException
{
}
