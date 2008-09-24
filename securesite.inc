<?php
// $Id$

/**
 * @file
 * Secure Site log-in functions
 */

/**
 * Menu callback; handle restricted pages.
 */
function _securesite_403() {
  global $user, $base_path;
  if (empty($user->uid) && empty($_SESSION['securesite_guest']) && strpos(request_uri(), $base_path .'logout') !== 0) {
    _securesite_user_authenticate();
  }
  else {
    $path = drupal_get_normal_path(variable_get('securesite_403', ''));
    menu_set_active_item($path);
    return menu_execute_active_handler($path);
  }
}

/**
 * Check user's credentials.
 */
function _securesite_login($edit) {
  global $user, $base_path;
  switch (variable_get('securesite_type', SECURESITE_BASIC)) {
    case SECURESITE_DIGEST:
      // If digest credentials are missing, skip to form log-in.
      if (isset($edit['response'])) {
        if (!empty($edit['name'])) {
          $pass = db_result(db_query("SELECT s.pass FROM {users} u INNER JOIN {securesite} s ON u.uid = s.uid WHERE u.name = '%s'", $edit['name']));
          $ha1 = md5("$edit[name]:$edit[realm]:$pass");
          $ha2 = md5($_SERVER['REQUEST_METHOD'] .':'. $edit['uri']);
          if ($edit['response'] == md5($ha1 .':'. $edit['nonce'] .':'. $edit['nc'] .':'. $edit['cnonce'] .':'. $edit['qop'] .':'. $ha2)) {
            $result = db_query("SELECT * FROM {users} WHERE LOWER(name) = LOWER('%s')", $edit['name']);
            if ($user = db_fetch_object($result)) {
              $user = drupal_unpack($user);
              $user->roles = array();
              if (!empty($user->uid)) {
                $user->roles[DRUPAL_AUTHENTICATED_RID] = 'authenticated user';
                $result = db_query('SELECT r.rid, r.name FROM {role} r INNER JOIN {users_roles} ur ON ur.rid = r.rid WHERE ur.uid = %d', $user->uid);
                while ($role = db_fetch_object($result)) {
                  $user->roles[$role->rid] = $role->name;
                }
                user_module_invoke('load', $edit, $user);
                user_authenticate_finalize($edit);
              }
            }
          }
          break;
        }
        $edit['pass'] = '';
      }
    case SECURESITE_BASIC:
    case SECURESITE_FORM:
      // The LDAP auth module can't use the regular external user log-in system, so
      // we have to call its log-in function directly.
      if (module_exists('ldapauth')) {
        ldapauth_authenticate($edit);
      }
      else {
        user_authenticate(array('name' => $edit['name'], 'pass' => $edit['pass']));
      }
      break;
  }
  if (empty($user->uid)) {
    // Check anonymous user permission and credentials
    $guest_name = variable_get('securesite_guest_name', '');
    $guest_pass = variable_get('securesite_guest_pass', '');
    if (!user_access('access secured pages') || !empty($guest_name) && $edit['name'] != $guest_name || !empty($guest_pass) && $edit['pass'] != $guest_pass) {
      _securesite_login_fail($edit);
    }
    else {
      // Mark this session to prevent re-login (note: guests can't log out).
      $_SESSION['securesite_guest'] = $edit['name'];
      $_SESSION['securesite_login'] = TRUE;
      // If path is front page, go to site root. Prevent a 403 error by redirecting off the logout page.
      if (drupal_is_front_page() || strpos(request_uri(), $base_path .'logout') === 0) {
        $path = '';
      }
      else {
        $path = $_GET['q']; // Redirect to prevent some caching problems.
      }
      drupal_goto($path);
    }
  }
  elseif (user_access('access secured pages')) {
    unset($_SESSION['securesite_guest']); // Clear the guest session.
    $_SESSION['securesite_login'] = TRUE; // Mark the session so Secure Site will be triggered on log-out.
    // If path is front page, go to site root. Prevent a log-in/log-out loop by redirecting off the log-out page.
    if (drupal_is_front_page() || strpos(request_uri(), $base_path .'logout') === 0) {
      $path = '';
    }
    else {
      $path = $_GET['q']; // Redirect to prevent some caching problems.
    }
    drupal_goto($path);
  }
  else { // Not an authorized user.
    drupal_set_message(t('Unauthorized user.'), 'error');
    _securesite_user_authenticate();
  }
}

/**
 * Handle log-in failure.
 */
function _securesite_login_fail($edit) {
  if (empty($edit['name'])) {
    watchdog('user', 'Log-in attempt failed for <em>anonymous</em> user.');
  }
  else {
    watchdog('user', 'Log-in attempt failed for %user.', array('%user' => $edit['name']));
  }
  drupal_set_message(t('Unrecognized user name and/or password.'), 'error');
  _securesite_user_authenticate();
}

/**
 * Display authentication dialog and send password reset mails.
 */
function _securesite_user_authenticate() {
  if (_securesite_forced()) {
    global $base_path;
    if (strpos(request_uri(), $base_path .'user/reset/') === 0) {
      $args = explode('/', $_GET['q']);
      // The password reset function doesn't work well if it doesn't have all the
      // required parameters or if the UID parameter isn't valid
      if (count($args) < 5 || user_load(array('uid' => $args[2], 'status' => 1)) == FALSE) {
        $error = t('You have tried to use an invalid one-time log-in link.');
        if (variable_get('securesite_request_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>') !== '') {
          $error .= ' '. t('Please request a new one using the form below.');
        }
        drupal_set_message($error, 'error');
      }
    }
    // Check if the user attempted to submit the password request form. If so, check
    // if we have information for the name/mail they entered and send it if we do.
    elseif (!empty($_POST['securesite_request_form'])) {
      _securesite_password_reset($_POST['edit']);
    }
    else {
      switch (variable_get('securesite_type', SECURESITE_BASIC)) {
        case SECURESITE_BASIC:
          _securesite_basic_authenticate();
          break;
        case SECURESITE_DIGEST:
          _securesite_digest_authenticate();
          break;
        case SECURESITE_FORM:
          _securesite_form_authenticate();
          break;
      }
    }
    module_invoke_all('exit', request_uri());
    session_write_close();
    exit();
  }
}

/**
 * Determine if Secure Site authentication should be forced.
 */
function _securesite_forced() {
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

/**
 * Process password reset requests.
 *
 * @param $edit
 * Username or e-mail address of user requesting password reset
 */
function _securesite_password_reset($edit = array()) {
  // Only look-up information if input was given
  if (($edit['name'] || $edit['mail'])) {
    // User must have an active account
    $load['status'] = 1;
    // Only create array keys/values if something was entered, otherwise
    // user_load() will fail
    if (!empty($edit['name'])) {
      $load['name'] = $edit['name'];
    }
    if (!empty($edit['mail'])) {
      $load['mail'] = $edit['mail'];
    }
    // Check account information
    $account = user_load($load);
    if (!empty($account->uid)) { // Valid account, e-mail the user a new password
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
        // Exit here because presumably the user can't do anything more before
        // visiting the password reset URL
        _securesite_dialog_page('<p id="mail">'. t('Further instructions have been e-mailed to you.') ."</p>\n");
        session_write_close();
        module_invoke_all('exit', request_uri());
        exit();
      }
      else {
        // Note: At this point, the user's password has already been reset
        watchdog('mail', 'Error mailing password to %name at %email.', array('%name' => $account->name, '%email' => $account->mail), WATCHDOG_ERROR);
        drupal_set_message(t('Unable to send e-mail. Please contact the site administrator.'), 'error');
      }
    }
    else { // Name or mail not valid or account disabled
      drupal_set_message(t('Unrecognized user name or e-mail address.'), 'error');
    }
  }
  else { // Nothing entered
    drupal_set_message(t('Unrecognized user name or e-mail address.'), 'error');
  }
}

function _securesite_basic_authenticate() {
  header('WWW-Authenticate: Basic realm="'. _securesite_realm() .'"');
  header('HTTP/1.0 401 Unauthorized');
  $output = _securesite_request_form();
  _securesite_dialog_page($output);
}

function _securesite_digest_authenticate() {
  $realm = _securesite_realm();
  header('WWW-Authenticate: Digest realm="'. $realm .'", qop="auth", nonce="'. uniqid() .'", opaque="'. md5($realm) .'"');
  header('HTTP/1.0 401 Unauthorized');
  _securesite_form_authenticate();
}

function _securesite_form_authenticate() {
  $status_msg = theme('status_messages');
  $status_msg = empty($status_msg) ? '' : '      '. $status_msg ."\n";
  $output = '<h1>'. t('Log in') .'</h1>'."\n";
  $output .= '    <div id="login">'."\n";
  $output .= '      '.  variable_get('securesite_login_form', '<p>'. t('Enter your user name and password.') .'</p>') ."\n";
  $output .= isset($_POST['securesite_request_form']) ? '' : $status_msg;
  $output .= '    </div>'."\n";
  $output .= '    <form action="'. request_uri() .'" method="post">'."\n";
  $output .= '      <p><label>'. t('Username') .': <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" value="" /></label></p>'."\n";
  $output .= '      <p><label>'. t('Password') .': <input type="password" class="form-password" maxlength="24" name="edit[pass]" id="edit-pass" value="" /></label></p>'."\n";
  $output .= '      <p><input type="hidden" name="securesite_login_form" value="1" /><input type="submit" class="form-submit" name="op" value="'. t('Log in') .'" /></p>'."\n";
  $output .= '    </form>'."\n";
  $request_form = _securesite_request_form();
  if (!empty($request_form)) {
    $output .= '    <hr />'."\n";
    $output .= $request_form;
  }
  _securesite_dialog_page($output);
}

/**
 * Return password reset form (if enabled) or log-in message.
 *
 * @return HTML string.
 */
function _securesite_request_form() {
  $output = '';
  $form_msg = variable_get('securesite_request_form', '<p>'. t('Enter your user name or e-mail address.') .'</p>');
  $status_msg = theme('status_messages');
  if (!empty($form_msg)) {
    $output .= '    <h1>'. t('Password Reset') .'</h1>'."\n";
    $output .= '    <div id="reset">'."\n";
    $output .= '      '. $form_msg ."\n";
    $output .= '    </div>'."\n";
    $output .= $status_msg;
    $output .= '    <form action="'. request_uri() .'" method="post">'."\n";
    $output .= '      <p><label>'. t('Username') .': <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" value="" /></label></p>'."\n";
    $output .= '      <p><label>'. t('E-mail address') .': <input type="text" maxlength="64" class="form-text" name="edit[mail]" id="edit-mail" value="" /></label></p>'."\n";
    $output .= '      <p><input type="hidden" name="securesite_request_form" value="1" /><input type="submit" class="form-submit" name="op" value="'. t('Reset password') .'" /></p>'."\n";
    $output .= '    </form>'."\n";
  }
  elseif (variable_get('securesite_type', SECURESITE_BASIC) == SECURESITE_BASIC) {
    // If password reset is disabled and the log-in form isn't being used,
    // output a message to the user informing them how to log in
    $output .= $status_msg;
    $output .= '<p id="password">'. t('Reload the page to try logging in again.') ."</p>\n";
  }
  return $output;
}

/**
 * Print HTML dialog page for Secure Site.
 *
 * @param $content
 * HTML to output for the log-in and/or password reset form
 */
function _securesite_dialog_page($content) {
  global $base_path;
  $theme_path = drupal_get_path('theme', variable_get('theme_default', 'garland'));
  $dialog_file = '/securesite-dialog.tpl.php';
  if (file_exists($theme_path . $dialog_file)) {
    include_once($theme_path . $dialog_file);
  }
  else {
    include_once(drupal_get_path('module', 'securesite') . $dialog_file);
  }
}

/**
 * Implementation of hook_mail().
 */
function securesite_mail($key, &$message, $params) {
  // Ignoring $key for now, since there's only one type of mail sent by Secure Site
  $message['subject'] = $params['subject'];
  $message['body'] = $params['body'];
}

function _securesite_realm() {
  $realm = variable_get('securesite_realm', variable_get('site_name', 'Drupal'));
  // If not on the home page of the site, Opera will not show the auth dialog
  // the first time after logout.  It will show the page displayed before
  // logging out.  Reloading will cause the dialog to display.  Safari
  // doesn't seem show the log-in/password request form when cancelling the
  // auth dialog no matter what.
  $user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '');
  if ($user_agent != str_replace(array('msie', 'opera', 'safari'), '', $user_agent)) {
    $realm .= ' - '. mt_rand(10, 999);
  }
  return $realm;
}

