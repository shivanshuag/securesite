#!/usr/bin/php
<?php
// $Id$

/**
 * @file
 * This file manages stored passwords. Only the root user should have access to
 * this file and the database used to store passwords.
 *
 * Usage: stored_passwords.php [OPTIONS]...
 *
 * Options:
 *   username=STRING  User identity.
 *   realm=STRING     Realm. Defaults to hostname.
 *   password=STRING  User password.
 *   op=STRING        Create or delete. By default, an existing user will be
 *                    updated.
 */

/**
 * Output a help message.
 */
foreach (array('-h', '--help', '-help', '-?', '/?', '?') as $arg) {
  if (in_array($arg, $argv)) {
    $output = 'Usage: stored_passwords.php [OPTIONS]...'."\n";
    $output .= "\n";
    $output .= 'Options:'."\n";
    $output .= '  username=STRING    User identity.'."\n";
    $output .= '  realm=STRING       Realm. Defaults to hostname.'."\n";
    $output .= '  password=STRING    User password.'."\n";
    $output .= '  op=STRING          Create or delete. By default, an existing user identity'."\n";
    $output .= '                     will be updated.'."\n";
    $output .= "\n";
    exit($output);
  }
}

/**
 * Get configuration file variables.
 */
require 'digest_md5.conf.php';

/**
 * Get command line variables.
 */
$edit = array();
array_shift($argv);
foreach ($argv as $arg) {
  list($key, $value) = explode('=', $arg, 2);
  $edit[$key] = $value;
}
$uname = posix_uname();
$edit['realm'] = isset($edit['realm']) ? $edit['realm'] : $uname['nodename'];

/**
 * Open a database connection.
 */
$cwd = getcwd();
chdir($drupal);
require "./includes/bootstrap.inc";
require_once "./includes/database.inc";
db_set_active();
chdir($cwd);
_securesite_schema();

/**
 * Execute command.
 */
if (isset($edit['name'])) {
  _securesite_password($edit);
}

/**
 * Work with stored passwords. This is a temporary placeholder function until we
 * can get an external program to do something similar.
 * @param $edit: An array of data with the following keys:
 * - name: User name
 * - realm: Site realm
 * - pass: User password
 * - op: The operation to be performed. If none is given, an existing user will be updated.
 * @return
 * A status string.
 */
function _securesite_password($edit) {
  $op = isset($edit['op']) ? $edit['op'] : NULL;
  switch ($op) {
    case 'create':
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['name'], $edit['realm'], 0, 1)) === FALSE) {
        $result = db_query("INSERT INTO {securesite_passwords} (name, realm, pass) VALUES ('%s', '%s', '%s')", $edit['name'], $edit['realm'], $edit['pass']);
        $output = $result === FALSE ? "Failed to add $edit[name] to $edit[realm]." : "Added $edit[name] to $edit[realm].";
      }
      else {
        unset($edit['op']);
        $output = _securesite_password($edit);
      }
      break;
    case 'delete':
      $result = db_query("DELETE FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['name'], $edit['realm']);
      $output = $result === FALSE ? "$edit[name] not found in $edit[realm]." : "Removed $edit[name] from $edit[realm].";
      break;
    default:
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['name'], $edit['realm'], 0, 1)) === FALSE) {
        $output = "$edit[name] does not exist in $edit[realm].";
      }
      else {
        $result = db_query("UPDATE {securesite_passwords} SET pass = '%s' WHERE name = '%s' AND realm = '%s'", $edit['pass'], $edit['name'], $edit['realm']);
        $output = $result === FALSE ? "Failed to update $edit[name] in $edit[realm]." : "Updated $edit[name] in $edit[realm].";
      }
      break;
  }
  exit("$output\n");
}

