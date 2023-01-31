<?php

namespace App\Controller;

use App\Controller\BaseController;

use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Contracts\Translation\TranslatorInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

use App\Security\AppAuthenticator;

/**
 * @Route("/", requirements={"_locale": "([a-z]{2})?"}, name="user_")
 */
class AuthController extends BaseController
{
    /**
     * Login.
     * @Route("{_locale}/account/login", name="login")
     * @Route("account/login", name="login-locale")
     * @param  Request               $request             Request instance
     * @param  LoggerInterface       $logger              Logger service
     * @param  TranslatorInterface   $translator          Translator service
     * @param  AuthenticationUtils   $authenticationUtils Authentication utility service
     * @param  UrlGeneratorInterface $urlGenerator        URL generator
     * @return Response                                   Response instance
     */
    public function login(
        Request $request,
        LoggerInterface $logger,
        TranslatorInterface $translator,
        AuthenticationUtils $authenticationUtils,
        UrlGeneratorInterface $urlGenerator,
    ): Response {
        if ($this->getUser()) {
            return $this->redirectWithMessage(AppAuthenticator::DEFAULT_AUTHED_ROUTE, [], "info", $translator->trans("You are already logged in.", [], "security"));
        }

        $error      = $authenticationUtils->getLastAuthenticationError();
        $response   = (new Response())->setStatusCode($error ? Response::HTTP_UNAUTHORIZED : Response::HTTP_OK);
        $sessParams = $request->getSession()->get("_target_path_params");
        $targetUrl  = $request->getSession()->has("_target_path")
            ? $urlGenerator->generate(strval($request->getSession()->get("_target_path")), is_array($sessParams) ? $sessParams : [], UrlGeneratorInterface::ABSOLUTE_URL)
            : null;

        return $this->render("login.html.twig", [
            "lastUsername"  => $authenticationUtils->getLastUsername(),
            "error"         => $error,
            "targetUrl"     => $targetUrl,
        ], $response);
    }

    /**
     * Login check.
     * @Route("account/login/check", name="login_check")
     * @return Response Response instance
     */
    public function loginCheck(): Response
    {
        throw new \LogicException("You're not supposed to be here.");
    }

    /**
     * Logout.
     * @Route("{_locale}/account/logout", name="logout")
     * @Route("account/logout", name="logout-locale")
     * @param  Request             $request    Request instance
     * @param  LoggerInterface     $logger     Logger service
     * @param  TranslatorInterface $translator Translator service
     * @return Response                        Response instance
     */
    public function logout(
        Request $request,
        LoggerInterface $logger,
        TranslatorInterface $translator,
    ): Response {
        if (!$this->getUser()) {
            return $this->redirectWithMessage(AppAuthenticator::DEFAULT_UNAUTHED_ROUTE, [], "danger", $translator->trans("You are not logged in.", [], "security"));
        }

        return $this->redirectToRoute(AppAuthenticator::DEFAULT_AUTHED_ROUTE);
    }
}
