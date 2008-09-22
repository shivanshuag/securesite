<?php
// $Id$

/**
 * @file
 * Secure Site admin pages
 */

function _securesite_admin_help() {
  return '<p>'. t('Secure Site allows site administrators to make a site or part of a site private. You can restrict access to the site by role. This means the site will be inaccessible to search engines and other crawlers, but you can still allow access to certain people.') .'</p>'."\n".
  '<p>'. t('You can also secure remote access to RSS feeds. You can keep content private and protected, but still allow users to get notification of new content and other actions via RSS with news readers that support <em>user:pass@example.com/node/feed</em> URLs, or have direct support for user name and password settings. This is especially useful when paired with the Organic Groups module or other node access systems.') .'</p>'."\n".
  '<h3>'. t('Configuration') .'</h3>'."\n".
  '<ul>'."\n".
  '  <li>'. t('Force authentication') ."\n".
  '    <p>'. t('This setting controls whether users will be forced to authenticate before viewing pages. By default, authentication is never forced.') .'</p>'."\n".
  '    <ol>'."\n".
  '      <li>'. t('Never') ."\n".
  '        <p>'. t('This setting will prevent Secure Site from hiding pages.') .'</p>'."\n".
  '      </li>'."\n".
  '      <li>'. t('Always') ."\n".
  '        <p>'. t('This setting will hide your entire site from unauthenticated users.') ."\n".
  '      </li>'."\n".
  '      <li>'. t('During maintenance') ."\n".
  '        <p>'. t('This setting will hide your site during maintenance.') ."\n".
  '      </li>'."\n".
  '      <li>'. t('On restricted pages') ."\n".
  '        <p>'. t('This setting will hide only pages that anonymous users cannot access.') ."\n".
  '      </li>'."\n".
  '    </ol>'."\n".
  '  </li>'."\n".
  '  <li>'. t('Authentication type') ."\n".
  '    <p>'. t('Two methods of authentication are available. Please note that the HTTP Auth method requires extra configuration if PHP is not installed as an Apache module. See the <a href="#issues">Known issues</a> section for a work-around.') ."\n".
  '    <ol>'."\n".
  '      <li>'. t('Use HTTP Auth') ."\n".
  '        <p>'. t('This will enable browser-based authentication. When a protected page is accessed, the user&rsquo;s web browser will display a user name and password log-in form. This is the recommend method for secure feeds.') .'</p>'."\n".
  '      </li>'."\n".
  '      <li>'. t('Use HTML log-in form') ."\n".
  '        <p>'. t('This method uses a themeable HTML log-in form for user name and password input. This method is the most reliable as it does not rely on the browser for authentication. This method does not work for secure feeds.') .'</p>'."\n".
  '      </li>'."\n".
  '    </ol>'."\n".
  '  </li>'."\n".
  '  <li>'. t('Authentication realm') ."\n".
  '    <p>'. t('You can use this field to name your log-in area. This is primarily used with HTTP Auth.') .'</p>'."\n".
  '  </li>'."\n".
  '  <li>'. t('Guest user name and password') ."\n".
  '    <p>'. t('If you give anonymous users the <em>!access</em> permission, you can set a user name and password for anonymous users. If not set, guests can use any name and password.', array('!access' => l('access secured pages', 'admin/user/permissions', array('fragment' => 'module-securesite')))) .'</p>'."\n".
  '  </li>'."\n".
  '  <li>'. t('Customize HTML forms') ."\n".
  '    <p>'. t('<em>Custom message for log-in form</em> and <em>Custom message for password reset form</em> are used in the HTML forms when they are displayed. If the latter box is empty, Secure Site will not offer to reset passwords. Please note, the log-in form is only displayed when the HTML log-in form authentication mode is used.') .'</p>'."\n".
  '  </li>'."\n".
  '</ul>'."\n".
  '<h3>'. t('Theming') .'</h3>'."\n".
  '<p>'. t('You can theme the HTML output of the Secure Site module using the file <em>securesite-dialog.tpl.php</em> found in the securesite directory. Copy <em>securesite-dialog.tpl.php</em> to your default theme. Now <em>securesite-dialog.tpl.php</em> will be used as a template for all Secure Site HTML output. <em>securesite-dialog.tpl.php</em> works in the same way as <em>page.tpl.php</em>.') .'</p>'."\n".
  '<h3><a name="issues">'. t('Known Issues') .'</a></h3>'."\n".
  '<ul>'."\n".
  '  <li>'. t('Authentication on PHP/CGI installations') ."\n".
  '    <p>'. t('If you are using HTTP Auth and are unable to log-in, PHP could be running in CGI mode. When run in CGI mode, the normal HTTP Auth log-in variables are not available to PHP. To work-around this issue, add the following rewrite rule at the end of the .htaccess file in Drupal&rsquo;s root installation directory:') .'</p>'."\n".
  '    <pre>RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]</pre>'."\n".
  '    <p>'. t('After making the suggested change in Drupal 5.7, the rewrite rules would look like this:') .'</p>'."\n".
  '    <pre># Rewrite current-style URLs of the form \'index.php?q=x\'.'."\n".
           'RewriteCond %{REQUEST_FILENAME} !-f'."\n".
           'RewriteCond %{REQUEST_FILENAME} !-d'."\n".
           'RewriteRule ^(.*)$ index.php?q=$1 [L,QSA]'."\n".
           'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]</pre>'."\n".
  '  </li>'."\n".
  '  <li>'. t('Authentication when running Drupal via IIS') ."\n".
  '    <p>'. t('If you are using HTTP Auth and are unable to log-in when Drupal is running on an IIS server, make sure that the PHP directive <em>cgi.rfc2616_headers</em> is set to <em>0</em> (the default value).') .'</p>'."\n".
  '  </li>'."\n".
  '</ul>'."\n";
}

/**
 * FAPI definition for Secure Site admin settings form
 * @ingroup forms
 * @see system_settings_form()
 * @see securesite_admin_settings_submit()
 */
function securesite_admin_settings() {
  global $base_url;
  $form['authentication'] = array(
    '#type' => 'fieldset',
    '#title' => t('Authentication'),
    '#description' => t('Enable Secure Site below. Users must have the <em>!access</em> permission in order to access the site once the following setting is enabled.', array('!access' => l(t('access secured pages'), 'admin/user/permissions', array('fragment' => 'module-securesite'))))
  );
  $form['authentication']['securesite_enabled'] = array(
    '#type' => 'radios',
    '#title' => t('Force authentication'),
    '#default_value' => variable_get('securesite_enabled', SECURESITE_DISABLED),
    '#options' => array(
      SECURESITE_DISABLED => t('Never'),
      SECURESITE_ALWAYS => t('Always'),
      SECURESITE_OFFLINE => t('During maintenance'),
      SECURESITE_403 => t('On restricted pages'),
    ),
    '#description' => t('Choose when to force authentication.'),
  );
  $form['authentication']['securesite_type'] = array(
    '#type' => 'radios',
    '#title' => t('Authentication type'),
    '#default_value' => variable_get('securesite_type', SECURESITE_AUTH),
    '#options' => array(
      SECURESITE_AUTH => t('Use HTTP Auth'),
      SECURESITE_FORM => t('Use HTML log-in form'),
    ),
    '#description' => t('HTTP Auth requires extra configuration if PHP is not installed as an Apache module. See the !link section of the Secure Site help for details.', array('!link' => l('Known issues', 'admin/help/securesite', array('fragment' => 'issues')))),
  );
  $form['authentication']['securesite_realm'] = array(
    '#type' => 'textfield',
    '#title' => t('Authentication realm'),
    '#default_value' => variable_get('securesite_realm', variable_get('site_name', 'Drupal')),
    '#length' => 30,
    '#maxlength' => 40,
    '#description' => t('Name to identify the log-in area in the HTTP Auth dialog.'),
  );
  $form['guest'] = array(
    '#type' => 'fieldset',
    '#title' => t('Guest access'),
    '#description' => t('Guest access allows anonymous users to view secure pages, though a user name and password are still required. If you give anonymous users the <em>!access</em> permission, you can set the user name and password for anonymous users below.', array('!access' => l('access secured pages', 'admin/user/permissions', array('fragment' => 'module-securesite')))),
  );
  $guest_access = !user_access('access secured pages', drupal_anonymous_user());
  $form['guest']['securesite_guest_name'] = array(
    '#type' => 'textfield',
    '#title' => t('Guest user'),
    '#default_value' => variable_get('securesite_guest_name', ''),
    '#length' => 30,
    '#maxlength' => 40,
    '#description' => t('Leave empty to accept any name.'),
    '#disabled' => $guest_access,
  );
  $form['guest']['securesite_guest_pass'] = array(
    '#type' => 'textfield',
    '#title' => t('Guest password'),
    '#default_value' => variable_get('securesite_guest_pass', ''),
    '#length' => 30,
    '#maxlength' => 40,
    '#description' => t('Leave empty to accept any password.'),
    '#disabled' => $guest_access,
  );
  $form['login_form'] = array(
    '#type' => 'fieldset',
    '#title' => t('Customize HTML forms'),
    '#description' => t('Configure the message displayed on the HTML log-in form (if enabled) and password reset form below.')
  );
  $form['login_form']['securesite_login_form'] = array(
    '#type' => 'textarea',
    '#title' => t('Custom message for HTML log-in form'),
    '#default_value' => variable_get('securesite_login_form', t('<p>Enter your user name and password:</p>')),
    '#length' => 60,
    '#height' => 3,
  );
  $form['login_form']['securesite_request_form'] = array(
    '#type' => 'textarea',
    '#title' => t('Custom message for password reset form'),
    '#default_value' => variable_get('securesite_request_form', t('<p>Enter your user name or e-mail address:</p>')),
    '#length' => 60,
    '#height' => 3,
    '#description' => t('Leave empty to disable Secure Site&rsquo;s password reset form.'),
  );
  $form['#submit'][] = 'securesite_admin_settings_submit';
  return system_settings_form($form);
}

/**
 * Restore core 403 error page when not using Secure Site page.
 */
function securesite_admin_settings_submit($form, &$form_state) {
  if ($form_state['values']['securesite_enabled'] != SECURESITE_403) {
    variable_set('site_403', variable_get('securesite_403', variable_get('site_403', '')));
    variable_del('securesite_403');
  }
}

