<?php

function _securesite_request_form() {
return '<p>Enter your username <strong><em>or</em></strong> your e-mail address.</p><div class="form-item">
<label for="edit-name">Username:</label><br />
<input type="text" maxlength="64" class="form-text" name="edit[name]" id="edit-name" size="30" value="" />
</div>
<div class="form-item">
<label for="edit-mail">E-mail address:</label><br />
<input type="text" maxlength="64" class="form-text" name="edit[mail]" id="edit-mail" size="30" value="" />
</div>
<input type="submit" class="form-submit" name="op" value="E-mail new password"  />';
}

function _securesite_user_pass() {
  global $base_url;
  $edit = $_POST['edit'];
  if ($edit['name'] && !($account = user_load(array('name' => $edit['name'], 'status' => 1)))) {
    $error = 1;
  }
  else if ($edit['mail'] && !($account = user_load(array('mail' => $edit['mail'], 'status' => 1)))) {
    $error = 1;
  }
  if ($account) {
    $from = variable_get('site_mail', ini_get('sendmail_from'));
    $pass = user_password();

    // Save new password:
    user_save($account, array('pass' => $pass));

    // Mail new password:
    $variables = array('%username' => $account->name, '%site' => variable_get('site_name', 'drupal'), '%password' => $pass, '%uri' => $base_url, '%uri_brief' => substr($base_url, strlen('http://')), '%mailto' => $account->mail, '%date' => format_date(time()), '%login_uri' => url('user', NULL, NULL, TRUE), '%edit_uri' => url('user/'. $account->uid .'/edit', NULL, NULL, TRUE));
    $subject = _user_mail_text('pass_subject', $variables);
    $body = _user_mail_text('pass_body', $variables);
    $headers = "From: $from\nReply-to: $from\nX-Mailer: Drupal\nReturn-path: $from\nErrors-to: $from";
    $mail_success = user_mail($account->mail, $subject, $body, $headers);
    if ($mail_success) {
      watchdog('user', securesite_t('Password mailed to %name at %email.', array('%name' => securesite_theme_placeholder($account->name), '%email' => securesite_theme_placeholder($account->mail))));
      print t('Your password and further instructions have been sent to your e-mail address.');
    }
    else {
      watchdog('user', securesite_t('Error mailing password to %name at %email.', array('%name' => securesite_theme_placeholder($account->name), '%email' => securesite_theme_placeholder($account->mail))), WATCHDOG_ERROR);
      print t('Unable to send mail. Please contact the site admin.');
    }
    securesite_goto();
  }
  else {
    if ($error) {
      print variable_get('securesite_error message', 'The name or the mail address is not recognized');
    }
    // Display form:
    $form = variable_get('securesite_request_form', _securesite_request_form());
    $form .= '<input type="hidden" name="securesite_request_form" value="1">';
    print '<form action="'. request_uri() .'" method="post">'. $form .'</form>';
  }
  exit;
}

function _securesite_settings() {
  $output = form_checkbox(t('Enable HTTP auth'), 'securesite_enabled', 1, variable_get('securesite_enabled', 0));
  $output .= form_textfield(t('Guest user'), 'securesite_guest_name', variable_get('securesite_guest_name', ''), 16, 40, t('Leave empty for no guest access'));
  $output .= form_textfield(t('Guest password'), 'securesite_guest_pass', variable_get('securesite_guest_pass', ''), 16, 40);
  $output .= form_textarea(t('HTML for the Request new password form'), 'securesite_request_form', variable_get('securesite_request_form', _securesite_request_form()), 60, 10);
  $output .= form_textfield(t('Error message for the Request new password form'), 'securesite_request_error', variable_get('securesite_request_error', 'The name or the mail address is not recognized'), 60, 100);
  return $output;
}
?>