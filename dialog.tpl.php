<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
<title><?php print variable_get('site_name', 'drupal'); ?></title>
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
<body>
  <div id="content">
    <div class="dialog"><?php print $content; ?></div>
  </div>
</body>
</html>
