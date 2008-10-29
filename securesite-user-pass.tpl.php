<?php
// $Id$

/**
 * @file securesite-user-pass.tpl.php
 */
?>
<h1><?php print t('Password reset') ?></h1>
<?php print $messages ?>
<p><?php print $title ?></p>
<?php print drupal_render($form['name']); ?>
<?php print drupal_render($form['submit']); ?>
<?php print drupal_render($form) ?>

