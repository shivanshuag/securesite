<?php
// $Id$

/**
 * returns complete form for login
 */
function _securesite_login_form() {
  return '<form action="'. request_uri() .'" method="post"><input type="hidden" name="securesite_login_form" value="1"><p>'. variable_get('securesite_login_form', 'Enter your '. variable_get('site_name', 'local') .' username and password.') .'</p>'. theme_status_messages() .
'<div class="form-item"><label for="edit-name">'. t('Username') .':</label> <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" size="30" value="" /></div>
<div class="form-item"><label for="edit-pass">'. t('Password') .':</label> <input type="password" class="form-password" maxlength="24" name="edit[pass]" id="edit-pass" size="12" value="" /></div>
<input type="submit" class="form-submit" name="op" value="Login" />
</form>';
}

/**
 * returns complete form for password reset request -if- securesite_request_form var exists
 */
function _securesite_request_form() {
  if ($formMsg = variable_get('securesite_request_form', t('Enter your username <strong><em>or</em></strong> your e-mail address.'))) {
    return '<form action="'. request_uri() .'" method="post"><input type="hidden" name="securesite_request_form" value="1"><p>'. $formMsg .'</p>'. theme_status_messages() .'<div class="form-item"><label for="edit-name">'. t('Username') .
':</label> <input type="text" maxlength="55" class="form-text" name="edit[name]" id="edit-name" size="30" value="" /></div>
<div class="form-item"><label for="edit-mail">'.t('E-mail address').':</label> <input type="text" maxlength="64" class="form-text" name="edit[mail]" id="edit-mail" size="30" value="" /></div>
<input type="submit" class="form-submit" name="op" value="'.t('E-mail new password').'" />
</form>';
  }
  return '';
}

/**
 * prints dialog page, should be moved to theme.inc and expanded for error reporting and no DB connection
 */
function dialog_page($content) {

  // Display themed dialog
  $themes      = list_themes();
  $theme       = variable_get('theme_default', 'bluemarine');
  $dialog_file = dirname($themes[$theme]->filename) .'/securesite-dialog.tpl.php';
  if (file_exists($dialog_file)) {
    include_once($dialog_file);
  }
  else {
    // Display default dialog
    print '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<title>'. variable_get('site_name', 'drupal') .'</title>
<style type="text/css" media="all">
body { font-family: Verdana, Geneva, Arial, Helvetica, sans-serif; font-size: 11px; margin: 50px auto; text-align: center; }
#content { width: 300px; margin: 0 auto; }
.dialog { border: 1px #000066 solid; margin-bottom: 20px; text-align: left; padding: 10px; clear: both; }
.dialog p {font-weight: bold; background: #000066; color: #FFFFFF; padding: 5px; margin: 0 0 10px 0;}
.error { color: #ff0000; padding-bottom: 5px; }
label { position: absolute; width: 100px; }
input, textarea { margin-left: 110px; width: 165px; margin-bottom: 5px; }
.form-submit { width: auto; padding: 0; margin: 0 0 10px 0; }
form { padding: 0; margin: 0; }
</style>
</head>
<body><div id="content"><div class="dialog">'. $content .'</div></div></body>
</html>';
  }
}

