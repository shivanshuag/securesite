<?php
// $Id$

/**
 * @file securesite-user-login.tpl.php
 */
?>
<h1><?php print t('Log in') ?></h1>
<?php print $messages ?>
<p><?php print $title ?></p>
<?php print drupal_render($form['openid_identifier']); ?>
<?php print drupal_render($form['name']); ?>
<?php print drupal_render($form['pass']); ?>
<?php print drupal_render($form['submit']); ?>
<?php print drupal_render($form['openid_links']); ?>
<?php print drupal_render($form); ?>
<span></span>

