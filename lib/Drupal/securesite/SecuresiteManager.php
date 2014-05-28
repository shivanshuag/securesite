<?php
/**
 * @file
 * Contains \Drupal\securesite\SecuresiteManager.
 */

namespace Drupal\securesite;

use Drupal\Core\Authentication\AuthenticationManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Drupal\Component\Utility\Unicode;
use Drupal\Core\Session\AnonymousUserSession;

//use Drupal\basic_auth\Authentication\Provider\BasicAuth;

class SecuresiteManager implements SecuresiteManagerInterface {

  /**
   * {@inheritdoc}
   */
  public function getMechanism(Request $request){
    static $mechanism;
    if (!isset($mechanism)) {
      // PHP in CGI mode work-arounds. Sometimes "REDIRECT_" prefixes $_SERVER
      // variables. See http://www.php.net/reserved.variables.
      if (empty($request->headers->get('HTTP_AUTHORIZATION')) && !empty($request->headers->get('REDIRECT_HTTP_AUTHORIZATION'))) {
        $request->headers->set('HTTP_AUTHORIZATION', $request->headers->get('REDIRECT_HTTP_AUTHORIZATION'));
      }
      if (!empty($request->headers->get('HTTP_AUTHORIZATION'))) {
        list($type, $authorization) = explode(' ', $request->headers->get('HTTP_AUTHORIZATION'), 2);
        switch (Unicode::strtolower($type)) {
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
      debug(SECURESITE_FORM);
      $mechanism = FALSE;
      $types = \Drupal::config('securesite.settings')->get('securesite_type');
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
  public function boot($type, Request $request, AuthenticationManager $authManager){
    $user = \Drupal::currentUser();
    switch ($type) {
      case SECURESITE_DIGEST:
        $edit = _securesite_parse_directives($_SERVER['PHP_AUTH_DIGEST']);
        $edit['name'] = $edit['username'];
        $edit['pass'] = NULL;
        $function = '_securesite_digest_auth';
        break;
      case SECURESITE_BASIC:
        //todo bleeding edge here. be careful here and verify with securesite.inc
        $basicAuthProvider = $authManager->getSortedProviders()['basic_auth'];
        $account = $basicAuthProvider->authenticate($request);
        if($account){
          //\Drupal::currentUser()->setAccount(new AnonymousUserSession());
        }
        debug(\Drupal::currentUser()->getRoles());
        //$edit['name'] = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
        //$edit['pass'] = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';
        //$function = '_securesite_plain_auth';
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
    // Are credentials different from current user?
/*    if ((!isset($user->name) || $edit['name'] !== $user->name) && (!isset($_SESSION['securesite_guest']) || $edit['name'] !== $_SESSION['securesite_guest'])) {
      $function($edit);
    }*/

  }


  public function showDialog($type, Request $request) {
    $response =  new Response();
    switch ($type) {
      case SECURESITE_BASIC:
        debug('visited showDialog');
        $response->setStatusCode(401);
        $response->headers->set('WWW-Authenticate', 'Basic realm="' . $this->getFakeRealm($request) . '"');
        break;
    }
    return $response;
  }

  /**
   * Determine if Secure Site authentication should be forced.
   */
  public function forcedAuth() {
    // Do we require credentials to display this page?
/*    if (php_sapi_name() == 'cli' || $_GET['q'] == 'admin/reports/request-test') {
      return FALSE;
    }*/
 //   else {
      switch (\Drupal::config('securesite.settings')->get('securesite_enabled')) {
        case SECURESITE_ALWAYS:
          return TRUE;
        case SECURESITE_OFFLINE:
          return(\Drupal::state()->get('system.maintenance_mode') ?: 0);
        default:
          return FALSE;
      }
 //   }
  }

  /**
   * Opera and Internet Explorer save credentials indefinitely and will keep
   * attempting to use them even when they have failed multiple times. We add a
   * random string to the realm to allow users to log out.
   */
  protected function getFakeRealm(Request $request) {
    $realm = \Drupal::config('securesite.settings')->get('securesite_realm');
    $user_agent = drupal_strtolower($request->server->get('HTTP_USER_AGENT', ''));
    if ($user_agent != str_replace(array('msie', 'opera'), '', $user_agent)) {
      $realm .= ' - ' . mt_rand(10, 999);
    }
    return $realm;
  }
}

