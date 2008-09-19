$Id$

The Secure Site module allows site administrators to make a site or part of a
site private. You can restrict access to the site by role. This means the site
will be inaccessible to search engines and other crawlers, but you can still
allow access to certain people.

You can also secure remote access to RSS feeds. You can keep content private and
protected, but still allow users to get notification of new content and other
actions via RSS with news readers that support user:pass@example.com/node/feed
URLs, or have direct support for user name and password settings. This is
especially useful when paired with the Organic Groups module or other node
access systems.


Installation
------------

  1. Place the entire securesite directory into your sites/all/modules
     directory.

  2. Enable the Secure Site module by navigating to:

     Administer >> Site building >> Modules

  3. Configure the Secure Site permissions:

     Administer >> User management >> Permissions

     Set the user roles that are allowed to access secured pages by giving those
     roles the "access secured pages" permission.

  4. Configure the Secure Site module:

     Administer >> Site configuration >> Secure Site


Configuration
-------------

  - Force authentication

    This setting controls whether users will be forced to authenticate before
    viewing pages. By default, authentication is never forced.

    1. Never

       This setting will prevent Secure Site from hiding pages.

    2. Always

       This setting will hide your entire site from unauthenticated users.

    3. During maintenance

       This setting will hide your site during maintenance.

    4. On restricted pages

       This setting will hide only pages that anonymous users cannot access.

  - Authentication type

    Two methods of authentication are available. Please note that the HTTP Auth
    method requires extra configuration if PHP is not installed as an Apache
    module. See the Known issues section of this file for a work-around.

    1. Use HTTP Auth

       This will enable browser-based authentication. When a protected page is
       accessed, the user's web browser will display a user name and password
       log-in form. This is the recommend method for secure feeds.

    2. Use HTML log-in form

       This method uses a themeable HTML log-in form for user name and password
       input. This method is the most reliable as it does not rely on the
       browser for authentication. This method does not work for secure feeds.

  - Authentication realm

    You can use this field to name your login area. This is primarily used with
    HTTP Auth.

  - Guest user name and password

    If you give anonymous users the "access secured pages" permission, you can
    set a user name and password for anonymous users. If not set, guests can use
    any name and password.

  - Customize HTML forms

    "Custom message for login form" and "Custom message for password reset form"
    are used in the HTML forms when they are displayed. If the latter box is
    empty, Secure Site will not offer to reset passwords. Please note, the login
    form is only displayed when the HTML login form authentication mode is used.


Theming
-------

You can theme the HTML output of the Secure Site module using the file
securesite-dialog.tpl.php found in the securesite directory. Copy
securesite-dialog.tpl.php to your default theme. Now securesite-dialog.tpl.php
will be used as a template for all Secure Site HTML output.
securesite-dialog.tpl.php works in the same way as page.tpl.php.


Known Issues
------------

  - Authentication on PHP/CGI installations

    If you are using HTTP Auth and are unable to login, PHP could be running in
    CGI mode. When run in CGI mode, the normal HTTP Auth login variables are not
    available to PHP. To work-around this issue, add the following rewrite rule
    at the end of the .htaccess file in Drupal's root installation directory:

    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]

    After making the suggested change in Drupal 6, the rewrite rules would
    look like this:

    # Rewrite URLs of the form 'x' to the form 'index.php?q=x'.
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} !=/favicon.ico
    RewriteRule ^(.*)$ index.php?q=$1 [L,QSA]
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]

  - Authentication when running Drupal via IIS

    If you are using HTTP Auth and are unable to login when Drupal is running on
    an IIS server, make sure that the PHP directive cgi.rfc2616_headers is set
    to 0 (the default value).

