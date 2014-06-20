<?php
/**
 * @file
 * Contains \Drupal\securesite\SecuresiteManager.
 */

namespace Drupal\securesite;

use Drupal\Core\Authentication\AuthenticationManager;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\user\UserAuthInterface;

//use Drupal\basic_auth\Authentication\Provider\BasicAuth;

class SecuresiteManager implements SecuresiteManagerInterface {

  /**
   * The page request to act on.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;
  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  protected $configFactory;

  /**
   * The user auth service.
   *
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

  public function __construct(EntityManagerInterface $entity_manager, ConfigFactoryInterface $config_factory, UserAuthInterface $user_auth){
    $this->entityManager = $entity_manager;
    $this->configFactory = $config_factory;
    $this->userAuth = $user_auth;
  }
  /**
   * {@inheritdoc}
   */
  public function setRequest(Request $request) {
    $this->request = $request;
  }

  /**
   * {@inheritdoc}
   */
  public function getMechanism() {
    static $mechanism;
    $request = $this->request;
    if (!isset($mechanism)) {
      // PHP in CGI mode work-arounds. Sometimes "REDIRECT_" prefixes $_SERVER
      // variables. See http://www.php.net/reserved.variables.
      if (empty($request->headers->get('HTTP_AUTHORIZATION')) && !empty($request->headers->get('REDIRECT_HTTP_AUTHORIZATION'))) {
        $request->headers->set('HTTP_AUTHORIZATION', $request->headers->get('REDIRECT_HTTP_AUTHORIZATION'));
      }
      if (!empty($request->headers->get('HTTP_AUTHORIZATION'))) {
        list($type, $authorization) = explode(' ', $request->headers->get('HTTP_AUTHORIZATION'), 2);
        switch (drupal_strtolower($type)) {
          case 'digest':
            $request->headers->set('PHP_AUTH_DIGEST', $authorization);
            break;
          case 'basic':
            $credentials = explode(':', base64_decode($authorization), 2);
            $request->headers->set('PHP_AUTH_USER', $credentials[0]);
            $request->headers->set('PHP_AUTH_PW', $credentials[1]);
            break;
        }
      }
      $mechanism = FALSE;
      $types = $this->configFactory->get('securesite.settings')->get('securesite_type');
      rsort($types, SORT_NUMERIC);
      foreach ($types as $type) {
        switch ($type) {
          case SECURESITE_DIGEST:
            //todo replaced isset with != null. check for side effects
            if ($request->headers->get('PHP_AUTH_DIGEST') != null) {
              $mechanism = SECURESITE_DIGEST;
              break 2;
            }
            break;
          case SECURESITE_BASIC:
            if (($request->headers->get('PHP_AUTH_USER') != null) || ($request->headers->get('PHP_AUTH_PW') != null)) {
              $mechanism = SECURESITE_BASIC;
              break 2;
            }
            break;
          case SECURESITE_FORM:
            //todo check $_POST
            if (isset($_POST['form_id']) && $_POST['form_id'] == 'securesite_user_login_form') {
              $mechanism = SECURESITE_FORM;
              break 2;
            }
            break;
        }
      }
    }
    return $mechanism;
  }

  /**
   * {@inheritdoc}
   */
  public function boot($type) {
    $currentUser = \Drupal::currentUser();
    $request = $this->request;

    switch ($type) {
      case SECURESITE_DIGEST:
        $edit = _securesite_parse_directives($_SERVER['PHP_AUTH_DIGEST']);
        $edit['name'] = $edit['username'];
        $edit['pass'] = NULL;
        $function = '_securesite_digest_auth';
        break;
      case SECURESITE_BASIC:
        var_dump('basic');
        $edit['name'] = $request->headers->get('PHP_AUTH_USER', '');
        $edit['pass'] = $request->headers->get('PHP_AUTH_PW', '');
        var_dump($edit);
        $function = 'plainAuth';
        break;
      case SECURESITE_FORM:
        //todo check if openid works
        if (!empty($_POST['openid_identifier'])) {
          openid_begin($_POST['openid_identifier'], $_POST['openid.return_to']);
        }
        $edit = array('name' => $_POST['name'], 'pass' => $_POST['pass']);
        $function = '_securesite_plain_auth';
        break;
    }
    var_dump($function);
    // Are credentials different from current user?
    $differentUser = ($currentUser->getUsername() == \Drupal::config('user.settings')->get('anonymous')) || ($edit['name'] !== $currentUser->getUsername());
    //var_dump($differentUser);
    $notGuestLogin = !isset($_SESSION['securesite_guest']) || $edit['name'] !== $_SESSION['securesite_guest'];
    var_dump($notGuestLogin);

    if ($differentUser && $notGuestLogin) {
      var_dump('calling plainauth');
      return ($this->$function($edit, $request));
    }
    //todo check this
    else {
      return $currentUser;
    }
  }


  public function plainAuth($edit) {
    // We cant set username to be a required field so we check here if it is empty
    var_dump('inside plainauth');
    if (empty($edit['name'])) {
      drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
      //todo showDialog has no effect inside plainauth because this function is called in authmanager
      $this->showDialog($this->getType());
    }

    //$users = user_load_multiple(array(), array('name' => $edit['name'], 'status' => 1));
    //todo not checked whether status = 1
    $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $edit['name'], 'status' => 1));
    $account = reset($accounts);
    var_dump($account->id());
    if (!$account) {
      // Not a registered user.
      // If we have correct LDAP credentials, register this new user.
      if ( \Drupal::moduleHandler()->moduleExists('ldapauth') && _ldapauth_auth($edit['name'], $edit['pass'], TRUE) !== FALSE) {
        $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $edit['name'], 'status' => 1));
        $account = reset($accounts);
        // System should be setup correctly now, perform log-in.
        if($account != FALSE) {
          return $this->userLogin($edit, $account);
        }
      }
      else {
        // See if we have guest user credentials.
        $this->guestLogin($edit);
      }
    }
    else {
      if ( $this->userAuth->authenticate($edit['name'], $edit['pass']) || module_exists('ldapauth') && _ldapauth_auth($edit['name'], $edit['pass']) !== FALSE) {
        // Password is correct. Perform log-in.
        var_dump('correct password');
        return $this->userLogin($edit, $account);
      }
      else {
        // Request credentials using most secure authentication method.
        watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
        drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
        $this->showDialog($this->getType());
      }
    }

  }


  protected function userLogin($edit, AccountInterface $account) {
    global $user;
    if ($account->hasPermission('access secured pages')) {
      var_dump('has permission');
      //\Drupal::currentUser()->setAccount($account);
      $newUser = user_load($account->id());
      user_login_finalize($newUser);
      $this->request->headers->remove('Authorization');
      // Mark the session so Secure Site will be triggered on log-out.
      $_SESSION['securesite_login'] = TRUE;

      // Unset the session variable set by securesite_denied().
      unset($_SESSION['securesite_denied']);
      // Unset messages from previous log-in attempts.
      unset($_SESSION['messages']);
      // Clear the guest session.
      unset($_SESSION['securesite_guest']);

      // Prevent a log-in/log-out loop by redirecting off the log-out page.
      if (current_path() == 'user/logout') {
        var_dump('logging out');
        $response = new RedirectResponse('/');
        $response->send();

      }
      return $account;
    }
    else {
      _securesite_denied(t('You have not been authorized to log in to secured pages.'));
    }

  }

  protected function guestLogin($edit) {
    $request = $this->request;
    $config = \Drupal::config('securesite.settings');
    $guest_name = $config->get('securesite_guest_name');
    $guest_pass = $config->get('securesite_guest_pass');
    $anonymous_user = new AnonymousUserSession();
    // Check anonymous user permission and credentials.
    if ($anonymous_user->hasPermission('access secured pages') && (empty($guest_name) || $edit['name'] == $guest_name) && (empty($guest_pass) || $edit['pass'] == $guest_pass)) {
      // Unset the session variable set by securesite_denied().
      if(isset($_SESSION['securesite_denied'])){
        unset($_SESSION['securesite_denied']);
      }
      // Mark this session to prevent re-login (note: guests can't log out).
      $_SESSION['securesite_guest'] = $edit['name'];
      $_SESSION['securesite_login'] = TRUE;
      // Prevent a 403 error by redirecting off the logout page.
      if (current_path() == 'user/logout') {
        return new RedirectResponse('<front>');
      }
    }
    else {
      if (empty($edit['name'])) {
        watchdog('user', 'Log-in attempt failed for <em>anonymous</em> user.');
        _securesite_denied(t('Anonymous users are not allowed to log in to secured pages.'));
      }
      else {
        watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
        drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
        $this->showDialog(securesite_type_get());
      }
    }

  }

  public function showDialog($type) {
    //todo other types of authentication
    $response =  new Response();
    switch ($type) {
      case SECURESITE_BASIC:
        debug('visited showDialog');
        $response->setStatusCode(401);
        $response->headers->set('WWW-Authenticate', 'Basic realm="' . $this->getFakeRealm() . '"');
        break;
    }
    $response->send();
  }

  /**
   * Determine if Secure Site authentication should be forced.
   */
  public function forcedAuth() {
    // Do we require credentials to display this page?
    if (php_sapi_name() == 'cli' || current_path() == 'admin/reports/request-test') {
      return FALSE;
    }
    else {
      switch (\Drupal::config('securesite.settings')->get('securesite_enabled')) {
        case SECURESITE_ALWAYS:
          return TRUE;
        case SECURESITE_OFFLINE:
          return(\Drupal::state()->get('system.maintenance_mode') ?: 0);
        default:
          return FALSE;
      }
    }
  }

  /**
   * Opera and Internet Explorer save credentials indefinitely and will keep
   * attempting to use them even when they have failed multiple times. We add a
   * random string to the realm to allow users to log out.
   */
  protected function getFakeRealm() {
    $realm = \Drupal::config('securesite.settings')->get('securesite_realm');
    $user_agent = drupal_strtolower($this->request->server->get('HTTP_USER_AGENT', ''));
    if ($user_agent != str_replace(array('msie', 'opera'), '', $user_agent)) {
      $realm .= ' - ' . mt_rand(10, 999);
    }
    return $realm;
  }


  protected function getType() {
    $securesite_type = \Drupal::config('securesite.settings')->get('securesite_type');
    return array_pop($securesite_type);
  }
}