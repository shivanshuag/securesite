<?php

/**
 * @file
 * Contains \Drupal\securesite\Authentication\Provider\SecuresiteAuth.
 */

namespace Drupal\securesite\Authentication\Provider;

use Drupal\securesite\SecuresiteManagerInterface;

use \Drupal\Component\Utility\String;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\user\UserAuthInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Securesite authentication provider.
 */
class SecuresiteAuth implements AuthenticationProviderInterface {

  /**
   * The Securesite Manager
   *
   * @var \Drupal\securesite\SecuresiteManagerInterface
   */
  protected $securesiteManager;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * Constructs a HTTP basic authentication provider object.
   *
   * @param \Drupal\securesite\SecuresiteManagerInterface $securesite_manager
   *    The Securesite Manager
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *    The config factory.
   */
  public function __construct(SecuresiteManagerInterface $securesite_manager, ConfigFactoryInterface $config_factory) {
    $this->securesiteManager = $securesite_manager;
    $this->configFactory = $config_factory;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    var_dump('applies called');
    // Did the user send credentials that we accept?
    $this->securesiteManager->setRequest($request);
    $type = $this->securesiteManager->getMechanism();
    if ($type !== FALSE && (isset($_SESSION['securesite_repeat']) ? !$_SESSION['securesite_repeat'] : TRUE)) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    var_dump('authenticating');
    $account = $this->securesiteManager->boot($this->securesiteManager->getMechanism());
    if(!empty($account)) {
      var_dump('got account');
      return $account;
    }
    else {
      return NULL;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function cleanup(Request $request) {}

  /**
   * {@inheritdoc}
   */
  public function handleException(GetResponseForExceptionEvent $event) {
  }

}
