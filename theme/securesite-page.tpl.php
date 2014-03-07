<?php

/**
 * @file
 * Template for Secure Site pages.
 *
 * @see template_preprocess_page()
 */
?>
<link type="text/css" rel="stylesheet" media="all" href="<?php print $base_path . drupal_get_path('module', 'securesite') .'/theme/securesite.css' ?>" />
<?php print $messages ?>
<?php print $content ?>
