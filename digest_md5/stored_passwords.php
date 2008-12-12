#!/usr/bin/php
<?php
// $Id$

/**
 * @file
 * This script manages stored passwords. Only the root user should have access
 * to this script and the database used to store passwords.
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
  $edit[$key] = trim($value, '"');
}
$uname = posix_uname();
$edit['realm'] = isset($edit['realm']) ? $edit['realm'] : $uname['nodename'];

/**
 * Output a help message.
 */
if (isset($edit['username'])) {
  foreach (array('-h', '--help', '-help', '-?', '/?', '?') as $arg) {
    if (in_array($arg, $argv)) {
      _stored_passwords_help();
    }
  }
}
else {
  _stored_passwords_help();
}

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
_stored_passwords_manage($edit);

/**
 * Work with stored passwords.
 * @param $edit
 *   An array of data with the following keys:
 *   - username: User name
 *   - realm: Site realm
 *   - pass: User password
 *   - op: The operation to be performed. If none is given, an existing user will be updated.
 * @return
 *   None.
 */
function _stored_passwords_manage($edit) {
  $op = isset($edit['op']) ? $edit['op'] : NULL;
  switch ($op) {
    case 'create':
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['username'], $edit['realm'], 0, 1)) === FALSE) {
        $result = db_query("INSERT INTO {securesite_passwords} (name, realm, pass) VALUES ('%s', '%s', '%s')", $edit['username'], $edit['realm'], $edit['pass']);
        $output = $result === FALSE ? "Failed to add $edit[username] to $edit[realm]." : "Added $edit[username] to $edit[realm].";
      }
      else {
        unset($edit['op']);
        $output = _stored_passwords_manage($edit);
      }
      break;
    case 'delete':
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['username'], $edit['realm'], 0, 1)) === FALSE) {
        $output = "$edit[username] not found in $edit[realm].";
      }
      else {
        $result = db_query("DELETE FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['username'], $edit['realm']);
        $output = $result === FALSE ? "Failed to remove $edit[username] from $edit[realm]." : "Removed $edit[username] from $edit[realm].";
      }
      break;
    default:
      if (db_result(db_query_range("SELECT name FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $edit['username'], $edit['realm'], 0, 1)) === FALSE) {
        $output = "$edit[username] not found in $edit[realm].";
      }
      else {
        $result = db_query("UPDATE {securesite_passwords} SET pass = '%s' WHERE name = '%s' AND realm = '%s'", $edit['pass'], $edit['username'], $edit['realm']);
        $output = $result === FALSE ? "Failed to update $edit[username] in $edit[realm]." : "Updated $edit[username] in $edit[realm].";
      }
      break;
  }
  exit("$output\n");
}

/**
 * Display help message.
 */
function _stored_passwords_help() {
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

