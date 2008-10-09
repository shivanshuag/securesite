<?php
// $Id$

/**
 * @file
 * Secure Site log-in functions
 */

/**
 * Boot with selected authentication mechanism.
 */
function _securesite_boot($type) {
  global $user;
  switch ($type) {
    case SECURESITE_DIGEST:
      $parts = explode(',', trim($_SERVER['PHP_AUTH_DIGEST']));
      $edit = array();
      foreach ($parts as $part) {
        if (!empty($part)) {
          list($key, $value) = explode('=', trim($part), 2);
          $key = $key == 'username' ? 'name' : $key;
          $edit[$key] = trim($value, '"');
        }
      }
      $function = '_securesite_digest_auth';
      break;
    case SECURESITE_BASIC:
      $edit['name'] = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
      $edit['pass'] = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';
      $function = '_securesite_plain_auth';
      break;
    case SECURESITE_FORM:
      // Fix missing indexes.
      $edit = $_POST['edit'] + array('name' => '', 'pass' => '');
      $function = '_securesite_plain_auth';
      break;
  }
  // Are credentials different from current user?
  if ((!isset($user->name) || $edit['name'] !== $user->name) && (!isset($_SESSION['securesite_guest']) || $edit['name'] !== $_SESSION['securesite_guest'])) {
    $function($edit);
  }
}

/**
 * Menu callback; handle restricted pages.
 */
function _securesite_403() {
  global $user;
  if (empty($user->uid) && !isset($_SESSION['securesite_guest']) && $_GET['q'] != 'logout') {
    _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
  }
  else {
    $path = drupal_get_normal_path(variable_get('securesite_403', ''));
    menu_set_active_item($path);
    return menu_execute_active_handler($path);
  }
}

/**
 * Perform digest authentication.
 */
function _securesite_digest_auth($edit) {
  global $user;
  $account = user_load(array('name' => $edit['name'], 'status' => 1));
  // Are credentials for a registered user?
  if (!empty($account->uid)) {
    $realm = variable_get('securesite_realm', variable_get('site_name', 'Drupal'));
    $header = _securesite_digest_validate(array('header' => $_SERVER['PHP_AUTH_DIGEST'], 'method' => $_SERVER['REQUEST_METHOD'], 'uri' => request_uri(), 'srealm' => $realm));
    // Have we stored a password for this user?
    if ($header == 'unknown') {
      // Request credentials using next most secure authentication method.
      $mechanism = _securesite_mechanism();
      $types = variable_get('securesite_type', array(SECURESITE_BASIC));
      rsort($types);
      foreach ($types as $type) {
        if ($type < $mechanism) {
          break;
        }
      }
      watchdog('user', 'Secure log-in failed for %user.', array('%user' => $edit['name']));
      drupal_set_message(t('Secure log-in failed. Please try again.'), 'error');
      _securesite_dialog($type);
    }
    else {
      // Is the password correct?
      if (strpos($header, 'Authentication-Info') === 0) {
        $user = $account;
        user_authenticate_finalize($edit);
        header($header);
        _securesite_user_login();
      }
      else {
        // Request credentials using most secure authentication method.
        watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
        drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
        _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
      }
    }
  }
  $uri = parse_url(request_uri());
  $edit_uri = isset($edit['uri']) ? parse_url($edit['uri']) : NULL;
  $required = array('name', 'realm', 'nonce', 'uri', 'response');
  $required = isset($edit['qop']) ? $required + array('cnonce', 'opaque', 'nc') : $required;
  if (
    // URI matches current page.
    $uri['path'] == $edit_uri['path'] &&
    // Quality of protection fields are valid.
    (isset($edit['qop']) && $edit['qop'] == 'auth' || !isset($edit['qop']) && !isset($edit['nc'])) &&
    // Required fields are present.
    array_diff($required, array_keys($edit)) == array()
  ) {
    $pass = variable_get('securesite_guest_pass', '');
    $ha1 = md5("$edit[name]:$edit[realm]:$pass");
    $ha2 = md5("$_SERVER[REQUEST_METHOD]:$edit[uri]");
    if (isset($edit['qop'])) {
      $digest = md5("$ha1:$edit[nonce]:$edit[nc]:$edit[cnonce]:$edit[qop]:$ha2");
    }
    else {
      $digest = md5("$ha1:$edit[nonce]:$ha2");
    }
    if ($edit['response'] == $digest) {
      $edit['pass'] = $pass;
      if (isset($edit['qop'])) {
        $header[] = 'qop='. $edit['qop'];
        $header[] = 'cnonce="'. $edit['cnonce'] .'"';
        $header[] = 'nc='. $edit['nc'];
        $digest = md5("$ha1:$edit[nonce]:$edit[nc]:$edit[cnonce]:$edit[qop]:". md5(":$edit[uri]"));
      }
      else {
        $digest = md5("$ha1:$edit[nonce]:". md5(":$edit[uri]"));
      }
      $header[] = 'rspauth="'. $digest .'"';
      _securesite_digest_validate('Authentication-Info: '. implode(', ', $header), TRUE);
    }
    _securesite_guest_login($edit);
  }
  else {
    _securesite_digest_validate('HTTP/1.1 400 Bad Request', TRUE);
    _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
  }
}

/**
 * Get the result of digest validation.
 * @param $header: The HTTP Authorize header string.
 * @return
 * The validation status.
 */
function _securesite_digest_validate($edit = NULL, $guest = FALSE) {
  static $status;
  if (isset($edit)) {
    if ($guest) {
      $status = $edit;
    }
    else {
      module_load_include('inc', 'securesite', 'securesite.digest_md5');
      $status = _securesite_digest_md5($edit);
    }
  }
  return $status;
}

/**
 * Perform plain authentication.
 */
function _securesite_plain_auth($edit) {
  global $user;
  $account = user_load(array('name' => $edit['name'], 'status' => 1));
  // Are credentials for a registered user?
  if (!empty($account->uid)) {
    // The LDAP auth module can't use the regular external user log-in system, so we
    // have to call its log-in function directly.
    if (module_exists('ldapauth')) {
      ldapauth_authenticate($edit);
    }
    else {
      user_authenticate($edit);
    }
    if (!empty($user->uid)) {
      _securesite_user_login();
    }
    else {
      // Request credentials using most secure authentication method.
      watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
      drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
      _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
    }
  }
  _securesite_guest_login($edit);
}

/**
 * Log in authenticated user.
 */
function _securesite_user_login() {
  global $user;
  if (user_access('access secured pages')) {
    unset($_SESSION['securesite_guest']); // Clear the guest session.
    $_SESSION['securesite_login'] = TRUE; // Mark the session so Secure Site will be triggered on log-out.
    // If path is front page, go to site root. Prevent a log-in/log-out loop by redirecting off the log-out page.
    if (drupal_is_front_page() || $_GET['q'] == 'logout') {
      $path = '';
    }
    else {
      $path = $_GET['q']; // Redirect to prevent some caching problems.
    }
    drupal_goto($path);
  }
  // Not an authorized user.
  else {
    // Load the anonymous user.
    $user = drupal_anonymous_user();
    drupal_set_message(t('Unauthorized user.'), 'error');
    _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
  }
}

/**
 * Log in guest user.
 */
function _securesite_guest_login($edit) {
  $guest_name = variable_get('securesite_guest_name', '');
  $guest_pass = variable_get('securesite_guest_pass', '');
  // Check anonymous user permission and credentials.
  if (user_access('access secured pages') && (empty($guest_name) || $edit['name'] == $guest_name) && (empty($guest_pass) || $edit['pass'] == $guest_pass)) {
    // Mark this session to prevent re-login (note: guests can't log out).
    $_SESSION['securesite_guest'] = $edit['name'];
    $_SESSION['securesite_login'] = TRUE;
    // If path is front page, go to site root. Prevent a 403 error by redirecting off the logout page.
    if (drupal_is_front_page() || $_GET['q'] == 'logout') {
      $path = '';
    }
    else {
      $path = $_GET['q']; // Redirect to prevent some caching problems.
    }
    drupal_goto($path);
  }
  else {
    if (empty($edit['name'])) {
      watchdog('user', 'Log-in attempt failed for <em>anonymous</em> user.');
    }
    else {
      watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
    }
    drupal_set_message('        '. t('Unrecognized user name and/or password.') ."\n      ", 'error');
    _securesite_dialog(array_pop(variable_get('securesite_type', array(SECURESITE_BASIC))));
  }
}

/**
 * Display authentication dialog and send password reset mails.
 */
function _securesite_dialog($type) {
  // Has the password reset form been submitted?
  if (isset($_POST['securesite_reset_form'])) {
    $content = _securesite_password_reset($_POST['edit']);
  }
  // Are we on a password reset page?
  elseif (strpos($_GET['q'], 'user/reset/') === 0) {
    $args = explode('/', $_GET['q']);
    // The password reset function doesn't work well if it doesn't have all the
    // required parameters or if the UID parameter isn't valid
    if (count($args) < 5 || user_load(array('uid' => $args[2], 'status' => 1)) == FALSE) {
      $error = t('You have tried to use an invalid one-time log-in link.');
      $reset = variable_get('securesite_reset_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>');
      if (empty($reset)) {
        drupal_set_message('      '. $error ."\n    ", 'error');
        $status_msg = theme('status_messages');
        $content = empty($status_msg) ? '' : $status_msg;
      }
      else {
        $error .= ' '. t('Please request a new one using the form below.');
        drupal_set_message('        '. $error ."\n      ", 'error');
        $content = _securesite_reset_form();
      }
    }
  }
  else {
    // Display log-in dialog.
    switch ($type) {
      case SECURESITE_DIGEST:
        $header = _securesite_digest_validate();
        if (empty($header)) {
          $realm = variable_get('securesite_realm', variable_get('site_name', 'Drupal'));
          $header = _securesite_digest_validate(array('srealm' => $realm, 'crealm' => _securesite_client_realm(), 'opaque' => session_id(), 'qop' => 'auth'));
        }
        if (strpos($header, 'WWW-Authenticate') === 0) {
          header($header);
          header('HTTP/1.1 401 Unauthorized');
        }
        else {
          header($header);
        }
        $content = _securesite_dialog_html('<p id="password">'. t('Reload the page to try logging in again.') ."</p>\n");
        break;
      case SECURESITE_BASIC:
        header('WWW-Authenticate: Basic realm="'. _securesite_client_realm() .'"');
        header('HTTP/1.1 401 Unauthorized');
        $content = _securesite_dialog_html('<p id="password">'. t('Reload the page to try logging in again.') ."</p>\n");
        break;
      case SECURESITE_FORM:
        $content = _securesite_form_dialog();
        break;
    }
  }
  if (!empty($content)) {
    global $base_path;
    $theme_path = drupal_get_path('theme', variable_get('theme_default', 'garland'));
    $dialog_file = '/securesite-dialog.tpl.php';
    if (file_exists($theme_path . $dialog_file)) {
      include_once($theme_path . $dialog_file);
    }
    else {
      include_once(drupal_get_path('module', 'securesite') . $dialog_file);
    }
    module_invoke_all('exit');
    session_write_close();
    exit();
  }
}

/**
 * Determine if Secure Site authentication should be forced.
 */
function _securesite_forced() {
  global $base_path;
  // Do we require credentials to display this page?
  if (php_sapi_name() == 'cli' || request_uri() == $base_path .'cron.php') {
    return FALSE;
  }
  else {
    switch (variable_get('securesite_enabled', SECURESITE_DISABLED)) {
      case SECURESITE_ALWAYS:
        return TRUE;
      case SECURESITE_OFFLINE:
        return variable_get('site_offline', FALSE);
      case SECURESITE_403:
        if (variable_get('site_403', '') != 'securesite_403') {
          variable_set('securesite_403', variable_get('site_403', ''));
          variable_set('site_403', 'securesite_403');
        }
      default:
        return FALSE;
    }
  }
}

/**
 * Check if the user attempted to submit the password request form. If so, check
 * if we have information for the name/mail they entered and send it if we do.
 * @param $edit: Array containing username or e-mail address of user requesting
 * password reset
 * @return
 * An HTML string
 */
function _securesite_password_reset($edit) {
  $load = array('status' => 1);
  // Only create array keys/values if something was entered, otherwise user_load() will fail
  if (!empty($edit['name'])) {
    $load['name'] = $edit['name'];
  }
  if (!empty($edit['mail'])) {
    $load['mail'] = $edit['mail'];
  }
  $account = user_load($load);
  if (!empty($account->uid)) {
    // Generate a new password for this user
    $account = user_save($account, array('pass' => user_password()));
    // Mail new password
    $language = user_preferred_language($account);
    $variables = array(
      '!username' => $account->name,
      '!site' => variable_get('site_name', 'Drupal'),
      '!login_url' => user_pass_reset_url($account),
      '!uri' => $base_url,
      '!uri_brief' => preg_replace('`^https?://`i', '', $base_url),
      '!mailto' => $account->mail,
      '!date' => format_date(time()),
      '!login_uri' => url('user', array('absolute' => TRUE, 'language' => $language)),
      '!edit_uri' => url('user/'. $account->uid .'/edit', array('absolute' => TRUE, 'language' => $language)),
    );
    $params['subject'] = _user_mail_text('password_reset_subject', $language, $variables);
    $params['body'] = _user_mail_text('password_reset_body', $language, $variables);
    $message = drupal_mail('securesite', 'password', $account->mail, $language, $params);
    if ($message['result']) {
      watchdog('user', 'Password mailed to %name at %email.', array('%name' => $account->name, '%email' => $account->mail));
      $output = '<p id="mail">'. t('Further instructions have been e-mailed to you.') ."</p>\n";
    }
    else {
      // Note: At this point, the user's password has already been reset.
      watchdog('mail', 'Error mailing password to %name at %email.', array('%name' => $account->name, '%email' => $account->mail), WATCHDOG_ERROR);
      drupal_set_message('        '. t('Unable to send e-mail. Please contact the site administrator.') ."\n      ", 'error');
      $output = _securesite_dialog_html();
    }
  }
  else {
    // Name or mail not valid or account disabled.
    drupal_set_message('        '. t('Unrecognized user name or e-mail address.') ."\n      ", 'error');
    $output = _securesite_dialog_html();
  }
  return $output;
}

/**
 * Display fallback HTML for HTTP authentication dialogs. Safari will not load
 * this. Opera will not load this after log-out unless the page has been
 * reloaded and the authentication dialog has been displayed twice.
 */
function _securesite_dialog_html($message = NULL) {
  if (in_array(SECURESITE_FORM, variable_get('securesite_type', array(SECURESITE_BASIC)))) {
    $output = _securesite_form_dialog();
  }
  else {
    $reset = variable_get('securesite_reset_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>');
    if (!empty($reset) && _securesite_forced()) {
      $output = _securesite_reset_form();
    }
    else {
      $status_msg = theme('status_messages');
      $output = empty($status_msg) ? '' : '      '. $status_msg ."\n";
      $output .= $message;
    }
  }
  return $output;
}

/**
 * Display HTML form authentication dialog.
 */
function _securesite_form_dialog() {
  // If the reset form exists and was submitted, status messages should be displayed there.
  $reset = variable_get('securesite_reset_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>');
  if (empty($reset) || empty($_POST['securesite_reset_form'])) {
    $status_msg = theme('status_messages');
  }
  $form_msg = variable_get('securesite_login_form', '<p>'. t('Enter your user name and password.') .'</p>');
  $output = '<h1>'. t('Log in') .'</h1>'."\n";
  $output .= '    <div id="login">'."\n";
  $output .= empty($form_msg) ? '' : '      '. $form_msg ."\n";
  $output .= empty($status_msg) ? '' : '      '. $status_msg;
  $output .= '    </div>'."\n";
  $output .= '    <form action="'. request_uri() .'" method="post">'."\n";
  $output .= '      <p><label>'. t('Username') .': <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" value="" /></label></p>'."\n";
  $output .= '      <p><label>'. t('Password') .': <input type="password" class="form-password" maxlength="24" name="edit[pass]" id="edit-pass" value="" /></label></p>'."\n";
  $output .= '      <p><input type="hidden" name="securesite_login_form" value="1" /><input type="submit" class="form-submit" name="op" value="'. t('Log in') .'" /></p>'."\n";
  $output .= '    </form>'."\n";
  $output .= empty($reset) && _securesite_forced() ? '' : '    <hr />'."\n    ". _securesite_reset_form();
  return $output;
}

/**
 * Return password reset form (if enabled) or log-in message.
 *
 * @return HTML string.
 */
function _securesite_reset_form() {
  $status_msg = theme('status_messages');
  $form_msg = variable_get('securesite_reset_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>');
  $output = '';
  $output .= '<h1>'. t('Password reset') .'</h1>'."\n";
  $output .= '    <div id="reset">'."\n";
  $output .= empty($form_msg) ? '' : '      '. $form_msg ."\n";
  $output .= empty($status_msg) ? '' : '      '. $status_msg;
  $output .= '    </div>'."\n";
  $output .= '    <form action="'. request_uri() .'" method="post">'."\n";
  $output .= '      <p><label>'. t('Username') .': <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" value="" /></label></p>'."\n";
  $output .= '      <p><label>'. t('E-mail address') .': <input type="text" maxlength="64" class="form-text" name="edit[mail]" id="edit-mail" value="" /></label></p>'."\n";
  $output .= '      <p><input type="hidden" name="securesite_reset_form" value="1" /><input type="submit" class="form-submit" name="op" value="'. t('Reset password') .'" /></p>'."\n";
  $output .= '    </form>'."\n";
  return $output;
}

/**
 * Implementation of hook_mail().
 */
function securesite_mail($key, &$message, $params) {
  // Ignoring $key for now, since there's only one type of mail sent by Secure Site
  $message['subject'] = $params['subject'];
  $message['body'] = $params['body'];
}

/**
 * Opera and Internet Explorer save credentials indefinitely and will keep
 * attempting to use them even when they have failed multiple times. We add a
 * random string to the realm to allow users to log out.
 */
function _securesite_client_realm() {
  $realm = variable_get('securesite_realm', variable_get('site_name', 'Drupal'));
  $user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '');
  if ($user_agent != str_replace(array('msie', 'opera'), '', $user_agent)) {
    $realm .= ' - '. mt_rand(10, 999);
  }
  return $realm;
}

/**
 * Work with stored passwords. This is a temporary placeholder function until we
 * can get an external program to do something similar.
 * @param $edit: An array of data with the following keys:
 * - name: User name
 * - realm: Site realm
 * - pass: User password
 * @param $op: A string representing the operation to be performed. If none is
 * given, an existing user will be updated.
 * - create: Add a user.
 * - delete: Remove a user.
 * @return
 * A status string.
 */
function _securesite_password($edit, $op = NULL) {
  switch ($op) {
    case 'create':
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['name'], $edit['realm'], 0, 1)) === FALSE) {
        $result = db_query("INSERT INTO {securesite_passwords} (name, realm, pass) VALUES ('%s', '%s', '%s')", $edit['name'], $edit['realm'], $edit['pass']);
        $output = $result === FALSE ? t('Failed to add @user', array('@user' => $edit['name'])) : t('Added @user', array('@user' => $edit['name']));
      }
      else {
        $output = _securesite_password($edit);
      }
      break;
    case 'delete':
      $result = db_query("DELETE FORM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['name'], $edit['realm']);
      $output = $result === FALSE ? t('@user not found.', array('@user' => $edit['username'])) : t('Removed @user', array('@user' => $edit['name']));
      break;
    default:
      $result = db_query("UPDATE {securesite_passwords} SET pass = '%s' WHERE name = '%s' AND realm = '%s'", $edit['pass'], $edit['name'], $edit['realm']);
      $output = $result === FALSE ? t('Failed to update @user.', array('@user' => $edit['name'])) : t('Updated @user', array('@user' => $edit['name']));
      break;
  }
  return $output;
}

