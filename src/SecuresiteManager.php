<?php
/**
 * @file
 * Contains \Drupal\securesite\SecuresiteManager.
 */

namespace Drupal\securesite;

use Drupal\Core\Session\AccountInterface;
use Drupal\user\Entity\User;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\user\UserAuthInterface;
use \Drupal\Component\Utility\Xss;
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

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
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
    //$request->getMeachanism = 'getting mechanism';
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
            var_dump('digest is selected');
            //todo replaced isset with != null. check for side effects
            if ($_SERVER['PHP_AUTH_DIGEST'] != null) {
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
            if ( $request->request->get('form_id')!= null && $request->request->get('form_id') == 'securesite_user_login_form') {
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
        var_dump('boot digest');
        var_dump($_SERVER['PHP_AUTH_DIGEST']);
        $edit = $this->parseDirectives($_SERVER['PHP_AUTH_DIGEST']);
        $edit['name'] = $edit['username'];
        $edit['pass'] = NULL;
        $function = 'digestAuth';
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
        $edit = array('name' => $request->request->get('name'), 'pass' => $request->request->get('pass'));
        $function = 'plainAuth';
        break;
    }
    var_dump($function);
    // Are credentials different from current user?
    $differentUser = ($currentUser->getUsername() == \Drupal::config('user.settings')->get('anonymous')) || ($edit['name'] !== $currentUser->getUsername());
    //var_dump($differentUser);
    $notGuestLogin = !isset($_SESSION['securesite_guest']) || $edit['name'] !== $_SESSION['securesite_guest'];
    var_dump($notGuestLogin);

    if ($differentUser && $notGuestLogin) {
      var_dump('calling '.$function);
      $this->$function($edit);
    }
  }


  public function plainAuth($edit) {
    // We cant set username to be a required field so we check here if it is empty
    var_dump('inside plainauth');
    if (empty($edit['name'])) {
      drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
      $this->showDialog($this->getType());
    }

    //$users = user_load_multiple(array(), array('name' => $edit['name'], 'status' => 1));
    //todo not checked whether status = 1
    $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $edit['name'], 'status' => 1));
    $account = reset($accounts);
    //var_dump($account->id());
    if (!$account) {
      // Not a registered user.
      // If we have correct LDAP credentials, register this new user.
      if ( \Drupal::moduleHandler()->moduleExists('ldapauth') && _ldapauth_auth($edit['name'], $edit['pass'], TRUE) !== FALSE) {
        $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $edit['name'], 'status' => 1));
        $account = reset($accounts);
        // System should be setup correctly now, perform log-in.
        if($account != FALSE) {
          $this->userLogin($edit, $account);
        }
      }
      else {
        // See if we have guest user credentials.
        var_dump('wrong user, guest login');
        $this->guestLogin($edit);
      }
    }
    else {
      if ( $this->userAuth->authenticate($edit['name'], $edit['pass']) || module_exists('ldapauth') && _ldapauth_auth($edit['name'], $edit['pass']) !== FALSE) {
        // Password is correct. Perform log-in.
        var_dump('correct password');
        $this->userLogin($edit, $account);
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
      \Drupal::currentUser()->setAccount($account);
      $newUser = User::load($account->id());
      user_login_finalize($newUser);
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
        $response = new RedirectResponse('/');
        $response->send();

      }
      return $account;
    }
    else {
      $this->denied(t('You have not been authorized to log in to secured pages.'));
    }

  }

  protected function guestLogin($edit) {
    var_dump('guest login');
    //todo check if the function works correctly
    $request = $this->request;
    $config = \Drupal::config('securesite.settings');
    $guest_name = $config->get('securesite_guest_name');
    $guest_pass = $config->get('securesite_guest_pass');
    $anonymous_user = new AnonymousUserSession();
    // Check anonymous user permission and credentials.
    if ($anonymous_user->hasPermission('access secured pages') && (empty($guest_name) || $edit['name'] == $guest_name) && (empty($guest_pass) || $edit['pass'] == $guest_pass)) {
      // Unset the session variable set by securesite_denied().
      var_dump('has permission');
      if(isset($_SESSION['securesite_denied'])){
        unset($_SESSION['securesite_denied']);
      }
      // Mark this session to prevent re-login (note: guests can't log out).
      $_SESSION['securesite_guest'] = $edit['name'];
      $_SESSION['securesite_login'] = TRUE;
      // Prevent a 403 error by redirecting off the logout page.
      if (current_path() == 'user/logout') {
        $response = new RedirectResponse('/');
        $response->send();
      }
    }
    else {
      if (empty($edit['name'])) {
        watchdog('user', 'Log-in attempt failed for <em>anonymous</em> user.');
        //todo securesite denied
        $this->denied(t('Anonymous users are not allowed to log in to secured pages.'));
      }
      else {
        watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
        drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
        $this->showDialog($this->getType());
      }
    }

  }

  /**
   * Perform digest authentication.
   */
  public function digestAuth($edit){
    $request = $this->request;
    //$response =  new Response();
    $user = \Drupal::currentUser();
    $realm = \Drupal::config('securesite.settings')->get('securesite_realm');
    var_dump($_SERVER['REQUEST_METHOD']);
    $header = $this->_securesite_digest_validate($status, array('data' => $_SERVER['PHP_AUTH_DIGEST'], 'method' => $_SERVER['REQUEST_METHOD'], 'uri' => request_uri(), 'realm' => $realm));
    var_dump($header);
    $account = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $edit['name'], 'status' => 1));
    $account = reset($account);
    var_dump('after load');
    var_dump($edit);
    var_dump($status);
    if (!$account) {
      // Not a registered user. See if we have guest user credentials.
      switch ($status) {
        case 1:
          $this->request->securesiteHeaders += array('Status', '400 Bad Request');
/*          $response->setStatusCode(400);
          $response->send();*/
          $this->showDialog($this->getType());
          break;
        case 0:
          // Password is correct. Log user in.
          $this->request->securesiteHeaders += array($header['name'] => $header['value']);
          //drupal_add_http_header($header['name'], $header['value']);
          //$response->headers->set();
          //$response->send();
          $edit['pass'] = \Drupal::config('securesite.settings')->get('securesite_guest_pass');

        default:
          $this->guestLogin($edit);
          break;
      }
    }
    else {
      switch ($status) {
        case 0:
          // Password is correct. Log user in.
          var_dump('log the user in');
          var_dump($request->securesiteHeaders);
          $this->request->securesiteHeaders += array($header['name'] => $header['value']);
          $this->userLogin($edit, $account);
          break;
        case 2:
          // Password not stored. Request credentials using next most secure authentication method.
          $mechanism = $this->getMechanism();
          $types = \Drupal::config('securesite.settings')->get('securesite_type');
          rsort($types);
          foreach ($types as $type) {
            if ($type < $mechanism) {
              break;
            }
          }
          watchdog('user', 'Secure log-in failed for %user.', array('%user' => $edit['name']));
          drupal_set_message(t('Secure log-in failed. Please try again.'), 'error');
          $this->showDialog($type);
          break;
        case 1:
          $this->request->securesiteHeaders += array('Status', '400 Bad Request');
          //$response->send();
          $this->showDialog($this->getType());
        default:
          // Authentication failed. Request credentials using most secure authentication method.
          watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
          drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
          $this->showDialog($this->getType());
          break;
      }
    }
  }

  /**
   * Get the result of digest validation.
   *
   * @param $status
   *   Will be set to the return status of the validation script
   * @param $edit
   *   An array of parameters to pass to the validation script
   * @return
   *   An HTTP header string.
   */
  function _securesite_digest_validate(&$status, $edit = array()) {
    static $header;
    if (!empty($edit)) {
      $args = array();
      foreach ($edit as $key => $value) {
        $args[] = "$key=" . escapeshellarg($value);
      }
      $script = \Drupal::config('securesite.settings')->get('securesite_digest_script');
      $response = exec($script . ' ' . implode(' ', $args), $output, $status);
      var_dump($output);
      // drupal_set_header() is now drupal_add_http_header() and requires headers passed as name, value in an array.
      // The script returns a string, so we shall break it up as best we can. The existing code doesn't seem
      // to worry about correct data to append to 'WWW-Authenticate: ' etc so I won't add any for the D7 conversion.
/*      $response_explode = explode('=', $response);
      $name = array_shift($response_explode);
      $value = implode('=', $response_explode);*/

      if (isset($edit['data']) && empty($status)) {
        $header = array('name' => "Authentication-Info", 'value' => $response);
      }
      else {
        $header = array('name' => "WWW-Authenticate", 'value' => 'Digest '. $response);
      }
    }
    return $header;
  }


  public function showDialog($type) {
    global $base_path, $language;
    $request = $this->request;
    $response =  new Response();
    // Has the password reset form been submitted?
    //todo what is the use of the following if statement? why get the form and not display it?
    if (isset($_POST['form_id']) && $_POST['form_id'] == 'user_pass') {
      // Get form messages, but do not display form.
      \Drupal::formBuilder()->getForm('securesite_user_pass');
      $content = '';
    }
    // Are we on a password reset page?
    elseif (strpos(current_path(), 'user/reset/') === 0 || module_exists('locale') && $language->enabled && strpos(current_path(), $language->prefix . '/user/reset/') === 0) {
      var_dump('password reset page');
      $args = explode('/', current_path());
      if (module_exists('locale') && $language->enabled && $language->prefix != '') {
        // Remove the language argument.
        array_shift($args);
      }
      // The password reset function doesn't work well if it doesn't have all the
      // required parameters or if the UID parameter isn't valid
      //todo see if loadByProperties works
      if (count($args) < 5 || $this->entityManager->getStorage('user')->loadByProperties(array('uid' => $args[2], 'status' => 1)) == FALSE) {
        $error = t('You have tried to use an invalid one-time log-in link.');
        $reset = \Drupal::config('securesite.settings')->get('securesite_reset_form');
        if (empty($reset)) {
          drupal_set_message($error, 'error');
          $content = '';
        }
        else {
          $error .= ' ' . t('Please request a new one using the form below.');
          drupal_set_message($error, 'error');
          $content = \Drupal::formBuilder()->getForm('securesite_user_pass');
        }
      }
    }
    // Allow OpenID log-in page to bypass dialog.
    elseif (!module_exists('openid') || $_GET['q'] != 'openid/authenticate') {

      // Display log-in dialog.
      switch ($type) {
        case SECURESITE_DIGEST:
          var_dump('show dialog digest');
          $header = $this->_securesite_digest_validate($status);
          //var_dump($header);
          if (empty($header)) {
            var_dump('empty header');
            $realm = \Drupal::config('securesite.settings')->get('securesite_realm');
            var_dump($realm);
            $header = $this->_securesite_digest_validate($status, array('realm' => $realm, 'fakerealm' => $this->getFakeRealm()));
          }
          //var_dump($header);
          if (strpos($header, 'WWW-Authenticate') === 0) {
            //$response->setStatusCode(401);
            $this->request->securesiteHeaders += array('Status' => '401');
          }
          else {
           // $response->setStatusCode(401);
            $this->request->securesiteHeaders += array('Status' => '401');
            var_dump('set header');
            //$response->headers->set($header['name'], $header['value']);
            $this->request->securesiteHeaders += array($header['name'] => $header['value']);
          }
          //$response->send();
          //exit;
          break;
        case SECURESITE_BASIC:
          $this->request->securesiteHeaders += array('Status' => '401');
          //$response->setStatusCode(401);
          //$response->headers->set('WWW-Authenticate', 'Basic realm="' . $this->getFakeRealm() . '"');
          $this->request->securesiteHeaders += array('WWW-Authenticate' => 'Basic realm="' . $this->getFakeRealm() . '"');
          //$response->send();
          //exit;
        case SECURESITE_FORM:
          //$response->setStatusCode(200);
          $this->request->securesiteHeaders += array('Status' => '200');
          break;
      }
      // Form authentication doesn't work for cron, so allow cron.php to run
      // without authenticating when no other authentication type is enabled.
      if ((request_uri() != $base_path . 'cron.php' || \Drupal::config('securesite.settings')->get('securesite_type') != array(SECURESITE_FORM)) && in_array(SECURESITE_FORM, \Drupal::config('securesite.settings')->get('securesite_type'))) {
        var_dump(request_uri());
        //todo fix next line
        //drupal_set_title(t('Authentication required'));
        $content = $this->dialogPage();
      }
    }
    if (isset($content)) {
      // Theme and display output
      $html = _theme('securesite_page', array('content' => $content));
      $response->setContent($html);
      $response->headers->set('Content-Type', 'text/html');
      $response->send();
      exit;
    }
  }

  /**
   * Deny access to users who are not authorized to access secured pages.
   */
  function denied($message) {
    $request = $this->request;
    var_dump('denied');
    if (empty($_SESSION['securesite_denied'])) {
      var_dump('empty');
      // Unset messages from previous log-in attempts.
      if (isset($_SESSION['messages'])) {
        unset($_SESSION['messages']);
      }
      // Set a session variable so that the log-in dialog will be displayed when the page is reloaded.
      $_SESSION['securesite_denied'] = TRUE;
      var_dump('session set');
      $types = \Drupal::config('securesite.settings')->get('securesite_type');
      if(array_pop($types) != SECURESITE_FORM){
        $this->request->securesiteHeaders += array('Status' => '403');
      }
      //todo find alternative
      //drupal_set_title(t('Access denied'));

      else {
        drupal_set_message(Xss::Filter($message), 'error');

        // Theme and display output
        $content = $this->dialogPage();
        print _theme('securesite_page', array('content' => $content));

        // Exit
        exit();
      }
    }
    else {
      var_dump('already set');
      unset($_SESSION['securesite_denied']);
      // Safari will attempt to use old credentials before requesting new credentials
      // from the user. Logging out requires that the WWW-Authenticate header be sent
      // twice.
      $user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? drupal_strtolower($_SERVER['HTTP_USER_AGENT']) : '');
      if ($user_agent != str_replace('safari', '', $user_agent)) {
        $_SESSION['securesite_repeat'] = TRUE;
      }
      $types = \Drupal::config('securesite.settings')->get('securesite_type');
      //todo fix next few lines
      if (in_array(SECURESITE_DIGEST, $types)) {
        // Reset the digest header.
        $realm = \Drupal::config('securesite.settings')->get('securesite_realm');
        $this->_securesite_digest_validate($status, array('realm' => $realm, 'fakerealm' => _securesite_fake_realm()));
      }
      if($this->getType() == SECURESITE_FORM) {
        drupal_set_message(Xss::Filter($message), 'error');

        // Theme and display output
        $content = $this->dialogPage();
        print _theme('securesite_page', array('content' => $content));

        // Exit
        exit();
      }
      else {
        $this->showDialog($this->getType());
      }
    }
  }




  /**
   * Display fall-back HTML for HTTP authentication dialogs. Safari will not load
   * this. Opera will not load this after log-out unless the page has been
   * reloaded and the authentication dialog has been displayed twice.
   */
  public function dialogPage(){
    $formBuilder = \Drupal::formBuilder();
    $reset = \Drupal::config('securesite.settings')->get('securesite_reset_form');
    if (in_array(SECURESITE_FORM, \Drupal::config('securesite.settings')->get('securesite_type'))) {
      $user_login = $formBuilder->getForm('securesite_user_login_form');
      $output = render($user_login);
      if (!empty($reset)) {
        $user_pass = $formBuilder->getForm('securesite_user_pass');
        $output .= "<hr />\n" . render($user_pass);
      }
    }
    else {
      if (!empty($reset)) {
        $user_pass = $formBuilder->getForm('securesite_user_pass');
        $output = render($user_pass);
      }
      else {
        $output = '<p>' . t('Reload the page to try logging in again.') . '</p>';
      }
    }
    return $output;
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

  protected function parseDirectives($field_value) {
    $directives = array();
    foreach (explode(',', trim($field_value)) as $directive) {
      list($directive, $value) = explode('=', trim($directive), 2);
      $directives[$directive] = trim($value, '"');
    }
    return $directives;
  }

  /**
   * Menu callback; handle restricted pages.
   */
  public static function handle403() {
    global $user;
    if (empty($user->uid) && !isset($_SESSION['securesite_guest']) && $_GET['q'] != 'user/logout') {
      _securesite_dialog(securesite_type_get());
    }
    else {
      $path = \Drupal::service('path.alias_manager.cached')->getSystemPath(\Drupal::config('securesite.settings')->get('securesite_403'));
      menu_set_active_item($path);
      return menu_execute_active_handler($path);
    }
  }

}
