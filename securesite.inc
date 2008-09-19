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
 * Determine if Secure Site authentication should be forced.
 */
function _securesite_forced() {
  switch (variable_get('securesite_enabled', SECURESITE_DISABLED)) {
    case SECURESITE_ALWAYS:
      return TRUE;
    case SECURESITE_OFFLINE:
      return variable_get('site_offline', FALSE);
    default:
      return FALSE;
  }
}

/**
 * Display authentication dialog and send password reset mails
 */
function _securesite_user_authenticate() {
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
  elseif ((isset($_POST['securesite_request_form']) ? $_POST['securesite_request_form'] : '')) {
    _securesite_password_reset($_POST['edit']);
  }
  // If using HTTP Auth, send the appropriate headers, but only if the user hasn't
  // just submitted the password reset or log-in forms.
  elseif (variable_get('securesite_type', SECURESITE_AUTH) == SECURESITE_AUTH && empty($_POST['securesite_login_form']) && empty($_POST['securesite_request_form'])) {
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
    header('WWW-Authenticate: Basic realm="'. $realm .'"');
    header('HTTP/1.0 401 Unauthorized');
  }
  // Show the log-in form and/or password request form if user cancels HTTP Auth dialog.
  $content = '';
  if (variable_get('securesite_type', SECURESITE_AUTH) == SECURESITE_FORM) {
    $content .= _securesite_login_form();
  }
  $request_form = _securesite_request_form();
  if (!empty($content) && !empty($request_form)) {
    $content .= '    <hr />'."\n";
  }
  $content .= $request_form;
  _securesite_dialog_page($content);
  module_invoke_all('exit', request_uri());
  session_write_close();
  exit();
}

/**
 * Check user's credentials.
 */
function _securesite_login($edit) {
  global $user, $base_path;
  // The LDAP auth module can't use the regular external user log-in system, so
  // we have to call its log-in function directly.
  $account = $user;
  if (module_exists('ldapauth')) {
    ldapauth_authenticate($edit);
  }
  else {
    user_authenticate(array('name' => $edit['name'], 'pass' => $edit['pass']));
  }
  if (empty($user->uid)) {
    // Do anonymous users have permission to log in?
    if (user_access('access secured pages', drupal_anonymous_user())) {
      global $base_path;
      $guest_name = variable_get('securesite_guest_name', '');
      $guest_pass = variable_get('securesite_guest_pass', '');
      if ((empty($guest_name) || $edit['name'] == $guest_name) && (empty($guest_pass) || $edit['pass'] == $guest_pass)) {
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
      else {
        _securesite_login_fail($edit);
      }
    }
    else {
      _securesite_login_fail($edit);
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
 * Returns complete form for log-in when using the HTML form
 *
 * @return
 *   HTML used in the Secure Site dialog when the HTML log-in form is in use
 */
function _securesite_login_form() {
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
  return $output;
}

/**
 * Returns complete form for password reset request (if enabled)
 *
 * @return
 *   HTML used in the Secure Site dialog when the HTTP Auth dialog is cancelled
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
  elseif (variable_get('securesite_type', SECURESITE_AUTH) == SECURESITE_AUTH) {
    // If password reset is disabled and the log-in form isn't being used,
    // output a message to the user informing them how to log in
    $output .= $status_msg;
    $output .= '<p id="password">'. t('Reload the page to try logging in again.') ."</p>\n";
  }
  return $output;
}

/**
 * Print HTML dialog page for Secure Site
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
 * Process password reset requests
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

/**
 * Implementation of hook_mail()
 */
function securesite_mail($key, &$message, $params) {
  // Ignoring $key for now, since there's only one type of mail sent by Secure Site
  $message['subject'] = $params['subject'];
  $message['body'] = $params['body'];
}

