<?php

/**
 * @file
 * Contains \Drupal\securesite\Authentication\Provider\SecuresiteAuth.
 */

namespace Drupal\securesite\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\Component\Utility\Settings;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;

/**
 * Cookie based authentication provider.
 */
class SecuresiteAuth implements AuthenticationProviderInterface {

  /**
   * The session manager.
   *
   * @var \Drupal\Core\Session\SessionManagerInterface
   */
  protected $sessionManager;

  /**
   * Constructs a new Cookie authentication provider instance.
   *
   * @param \Drupal\Core\Session\SessionManagerInterface $session_manager
   *   The session manager.
   */
  public function __construct(SessionManagerInterface $session_manager) {
    $this->sessionManager = $session_manager;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    // Global $user is deprecated, but the session system is still based on it.
    var_dump('securesite auth');
    global $user;
    $start = $this->sessionManager->initialize()->isStarted();
    var_dump($start);
    if ($start) {
      return $user;
    }
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function cleanup(Request $request) {
    $this->sessionManager->save();
  }

  /**
   * {@inheritdoc}
   */
  public function handleException(GetResponseForExceptionEvent $event) {
    return FALSE;
  }
}
