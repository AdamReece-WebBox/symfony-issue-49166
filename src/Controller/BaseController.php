<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

abstract class BaseController extends AbstractController
{
    /*
    ----------------------------------------------------------------------------
        Date/time functions
    ----------------------------------------------------------------------------
     */

    /**
     * Create a date/time zone instance.
     * @param  string|null   $timeZone Time zone, or null to fallback on application/server configuration
     * @return \DateTimeZone
     */
    protected function createDateTimeZone(?string $timeZone = null): \DateTimeZone
    {
        return new \DateTimeZone($timeZone ?? $_SERVER["APP_TIMEZONE"] ?? date_default_timezone_get());
    }

    /**
     * Create a date/time instance.
     * @param  string|null        $time      Time, or null for now
     * @param  string|null        $timeZone  Time zone, or null to fallback on application/server configuration
     * @param  bool|null          $immutable Immutable instance
     * @return \DateTimeInterface            Instance of \DateTime or \DateTimeImmutable according to immutable argument
     */
    protected function createDateTime(?string $time = "now", ?string $timeZone = null, ?bool $immutable = true): \DateTimeInterface
    {
        if (empty($time)) {
            $time = "now";
        }

        $dtz    = $this->createDateTimeZone($timeZone);
        $dt     = $immutable ? new \DateTimeImmutable($time, $dtz) : new \DateTime($time, $dtz);

        if (!($dt instanceof \DateTimeInterface)) {
            throw new \UnexpectedValueException("Date/time interface could not be build.");
        }

        return $dt;
    }

    /**
     * Create a date/time instance from a specific format.
     * @param  string             $format    Format
     * @param  string             $time      Formatted date/time
     * @param  string|null        $timeZone  Time zone, or null to fallback on application/server configuration
     * @param  bool|null          $immutable Immutable instance
     * @return \DateTimeInterface            Instance of \DateTime or \DateTimeImmutable according to immutable argument
     */
    protected function createDateTimeFromFormat(string $format, string $time, ?string $timeZone = null, ?bool $immutable = true): \DateTimeInterface
    {
        $dtz    = $this->createDateTimeZone($timeZone);
        $dt     = $immutable ? \DateTimeImmutable::createFromFormat($format, $time, $dtz) : \DateTime::createFromFormat($format, $time, $dtz);

        if (!($dt instanceof \DateTimeInterface)) {
            throw new \UnexpectedValueException("Date/time interface could not be build.");
        }

        return $dt;
    }



    /*
    ----------------------------------------------------------------------------
        Response functions
    ----------------------------------------------------------------------------
     */

    /**
     * Shortcut to redirect with a flash message in one go.
     * Don't you just like functions where the docblock is longer than its payload? ha ha! :)
     * @param  string               $route      Redirect route
     * @param  array<string, mixed> $parameters Redirect parameters
     * @param  string               $type       Flash type
     * @param  string               $message    Flash message
     * @param  int                  $code       Response HTTP code
     * @return RedirectResponse                 Response instance
     */
    protected function redirectWithMessage(string $route, array $parameters = [], string $type = "info", string $message = "", int $code = Response::HTTP_FOUND): RedirectResponse
    {
        if (!($message = trim($message))) {
            throw new \UnexpectedValueException("Message not specified.");
        }

        $this->addFlash($type, $message);
        return $this->redirectToRoute($route, $parameters, $code);
    }



    /*
    ----------------------------------------------------------------------------
        User functions
    ----------------------------------------------------------------------------
     */

    /**
     * Get the current user.
     * @return User|null User entity, or null for anonymous
     */
    protected function getUser(): ?User
    {
        $user = parent::getUser();
        return ($user instanceof User ? $user : null);
    }
}
