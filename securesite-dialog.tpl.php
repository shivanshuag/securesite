<?php
// $Id$
?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <title><?php print variable_get('site_name', 'Drupal') ?></title>
    <link type="text/css" rel="stylesheet" media="all" href="<?php print $base_path . drupal_get_path('module', 'securesite') .'/securesite-dialog.css' ?>" />
  </head>
  <body>
    <?php print $content ?>
  </body>
</html>

