<?php

namespace App\Security;

use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\UserRepository;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

use App\Entity\User;

class AppAuthenticator extends AbstractAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    /*
    ----------------------------------------------------------------------------
        Traits
    ----------------------------------------------------------------------------
     */

    use TargetPathTrait;



    /*
    ----------------------------------------------------------------------------
        Constants & enumerators
    ----------------------------------------------------------------------------
     */

    /** @const string Login route name. */
    public const LOGIN_ROUTE            = "user_login";
    /** @const string Login check route name. */
    public const LOGIN_CHECK_ROUTE      = "user_login_check";
    /** @const string Logout route name. */
    public const LOGOUT_ROUTE           = "user_logout";
    /** @const string Default route name after authenticating. */
    public const DEFAULT_AUTHED_ROUTE   = "user_account";
    /** @const string Default route name after un-authenticating. */
    public const DEFAULT_UNAUTHED_ROUTE = "home_index";



    /*
    ----------------------------------------------------------------------------
        Variables
    ----------------------------------------------------------------------------
     */

    /** @var LoggerInterface $logger Logger service. */
    private $logger;

    /** @var TranslatorInterface $translator Translator service. */
    private $translator;

    /** @var UrlGeneratorInterface $urlGenerator URL generator. */
    private $urlGenerator;

    /** @var CsrfTokenManagerInterface $csrfTokenManager CSRF token manager. */
    private $csrfTokenManager;

    /** @var EntityManagerInterface $em Entity manager. */
    private $em;

    /** @var UserRepository $userRepository User entity repository. */
    private $userRepository;



    /*
    ----------------------------------------------------------------------------
        Life cycle functions
    ----------------------------------------------------------------------------
     */

    /**
     * Constructor.
     * @param LoggerInterface           $logger           Logger service
     * @param TranslatorInterface       $translator       Translator service
     * @param UrlGeneratorInterface     $urlGenerator     URL generator
     * @param CsrfTokenManagerInterface $csrfTokenManager CSRF token manager
     * @param EntityManagerInterface    $em               Entity manager
     * @param UserRepository            $userRepository   User entity repository
     */
    public function __construct(
        LoggerInterface $logger,
        TranslatorInterface $translator,
        UrlGeneratorInterface $urlGenerator,
        CsrfTokenManagerInterface $csrfTokenManager,
        EntityManagerInterface $em,
        UserRepository $userRepository
    ) {
        $this->logger           = $logger;
        $this->translator       = $translator;
        $this->urlGenerator     = $urlGenerator;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->em               = $em;
        $this->userRepository   = $userRepository;
    }



    /*
    ----------------------------------------------------------------------------
        AuthenticatorInterface functions
    ----------------------------------------------------------------------------
     */

    /** {@inheritdoc} */
    public function supports(Request $request): ?bool
    {
        if ($route = $request->attributes->get("_route")) {
            $routeAccepted = false;

            foreach ([self::LOGIN_ROUTE, self::LOGIN_CHECK_ROUTE] as $r) {
                if ($route === $r || preg_match(sprintf("/^%s-locale$/", $r), $route)) {
                    $routeAccepted = true;
                    break;
                }
            }

            if (!$routeAccepted) {
                $this->logger->debug("App authenticator not supported: Route invalid.", [
                    "route" => $request->attributes->get("_route"),
                ]);
                return false;
            }
        }

        if (!$request->isMethod(Request::METHOD_POST)) {
            $this->logger->debug("App authenticator not supported: Method invalid.", [
                "method" => $request->getMethod(),
            ]);
            return false;
        }

        return true;
    }

    /** {@inheritdoc} */
    public function authenticate(Request $request): Passport
    {
        $logContext = [
            "ipAddress"     => $request->getClientIp(),
            "username"      => null,
            "rememberMe"    => null,
        ];

        // Read form
        $username   = strval($request->request->get("_username"));
        $password   = strval($request->request->get("_password"));
        $rememberMe = boolval($request->request->get("_remember_me"));
        $csrfToken  = strval($request->request->get("_csrf_token"));

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        $logContext["username"]     = $username;
        $logContext["rememberMe"]   = $rememberMe;

        // Check form
        if (empty($username)) {
            throw new CustomUserMessageAuthenticationException($this->translator->trans("Empty username.", [], "security"));
        }

        if (empty($password)) {
            throw new CustomUserMessageAuthenticationException($this->translator->trans("Empty password.", [], "security"));
        }

        $token = new CsrfToken("authenticate", $csrfToken);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }

        // Retrieve user entity
        /** @var User|null $user Local user entity. */
        if (!($user = $this->userRepository->loadUserByIdentifier($username))) {
            throw new BadCredentialsException($this->translator->trans("Invalid credentials.", [], "security"));
        }

        // Issue passport
        $passport = new Passport(new UserBadge($user->getUsername()), new PasswordCredentials($password));

        if ($token instanceof CsrfToken) {
            $passport->addBadge(new CsrfTokenBadge($token->getId(), $token->getValue()));
        }

        if (!empty($rememberMe)) {
            $passport->addBadge(new RememberMeBadge());
        }

        $passport->setAttribute("user", $user);

        /** @var PasswordCredentials|null $passwordBadge */
        $passwordBadge = $passport->getBadge(PasswordCredentials::class);
        if ($passwordBadge instanceof PasswordCredentials) {
            $passwordBadge->markResolved();
        }

        $this->logger->notice("Passport issued.", [
            "ipAddress" => $request->getClientIp(),
            "username"  => $username,
            "user"      => $user,
            "passport"  => $passport,
        ]);

        // Update user last seen timestamp
        $user->setTimeStampLastSeen(new \DateTimeImmutable("now", new \DateTimeZone($_SERVER["APP_TIMEZONE"])));

        $this->em->persist($user);
        $this->em->flush();

        return $passport;
    }

    /** {@inheritdoc} */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $this->logger->notice("Passport check.", [
            "passport"  => $passport,
            "realm"     => $firewallName,
        ]);

        if (!($passport instanceof Passport)) {
            throw new \UnexpectedValueException("Passport invalid.");
        }

        /** @var User|null $user */
        $user = $passport->getAttribute("user");
        if (!($user instanceof User)) {
            throw new \UnexpectedValueException("User invalid.");
        }

        return new UsernamePasswordToken($user, $firewallName, $user->getRoles());
    }

    /** {@inheritdoc} */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->logger->info("App authentication successful.", [
            "ipAddress" => $request->getClientIp(),
            "username"  => $token->getUserIdentifier(),
            "user"      => $token->getUser(),
            "realm"     => $firewallName,
        ]);

        $request->getSession()->remove(Security::AUTHENTICATION_ERROR);
        $request->getSession()->remove(Security::LAST_USERNAME);

        return new RedirectResponse($this->getTargetPath($request->getSession(), $firewallName) ?: $this->getDefaultUrl());
    }

    /** {@inheritdoc} */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->logger->warning("App authentication failed.", [
            "ipAddress" => $request->getClientIp(),
            "username"  => $request->getSession()->get(Security::LAST_USERNAME),
            "reason"    => $exception->getMessage(),
        ]);

        $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception->getMessage());

        return null;
    }



    /*
    ----------------------------------------------------------------------------
        AuthenticationEntryPointInterface functions
    ----------------------------------------------------------------------------
     */

    /** {@inheritdoc} */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->getLoginUrl());
    }



    /*
    ----------------------------------------------------------------------------
        Helper functions
    ----------------------------------------------------------------------------
     */

    /**
     * Get the application login URL.
     * @return string URL to login
     */
    protected function getLoginUrl(): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }

    /**
     * Get the application logout URL.
     * @return string URL to logout
     */
    protected function getLogoutUrl(): string
    {
        return $this->urlGenerator->generate(self::LOGOUT_ROUTE);
    }

    /**
     * Get the application default URL.
     * @param  bool   $authed Is the user authenticated?
     * @return string         URL to exit to
     */
    protected function getDefaultUrl(?bool $authed = false): string
    {
        return $this->urlGenerator->generate($authed ? self::DEFAULT_AUTHED_ROUTE : self::DEFAULT_UNAUTHED_ROUTE);
    }

    /**
     * Create a commonly used "Bad credentials." exception, translated.
     * @param  string|null                              $message Detailed log message
     * @param  array<string, mixed>                     $context Detailed log context
     * @return CustomUserMessageAuthenticationException          Exception instance
     */
    private function createBadCredentialsException(?string $message, array $context = []): CustomUserMessageAuthenticationException
    {
        if (!empty($message)) {
            $this->logger->info(sprintf("App authentication failed details: %s", $message), $context);
        }

        return new CustomUserMessageAuthenticationException($this->translator->trans("Bad credentials.", [], "security"));
    }
}
