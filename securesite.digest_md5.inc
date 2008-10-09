<?php
// $Id$

/**
 * @file
 * DIGEST-MD5 authentication mechanism. This is a temporary placeholder. We do
 * not want PHP to be able to retrieve passwords. Because digest authentication
 * requires access to users' passwords, we will eventually depend on an external
 * program that cannot be used by PHP to retrieve the passwords.
 */

/**
 * If an Authorization header is received, use stored password to validate it.
 * Otherwise, send WWW-Authenticate header.
 *
 * This is a temporary placeholder function until we can get an external program
 * to do something similar. Configuration variables that can be set are
 * securesite_nonce_expires and securesite_max_nc.
 *
 * @param $edit: An array with any of the following keys:
 * - header: HTTP Authorize header string. If not given, a WWW-Authenticate
 *   header will be returned.
 * - srealm: The server realm in which the password and nonce are stored
 * - crealm: The realm sent to the client
 * - opaque: A session tracking value
 * - method: Method of the request
 * - qop: Quality of protection
 * - entity-body: The body of the message being sent before encoding
 * - uri: The URI of the requested resource
 *
 * Required for WWW-Authenticate request:
 * - crealm
 * - qop (defaults to "auth" if not given)
 *
 * Required for Authorize response:
 * - header
 * - uri
 * - method (defaults to "Authenticate" if not given)
 *
 * @return
 * 'valid', 'invalid', 'unknown', 'stale', 'replay', or nonce string.
 */
function _securesite_digest_md5($edit) {
  // Remove expired nonce values.
  $time = time();
  $expire = variable_get('securesite_nonce_expires', 60);
  if (!empty($expire)) {
    db_query("DELETE FROM {securesite_nonce} WHERE time < %d", $time - $expire);
  }
  if (isset($edit['header'])) {
    // Validate digest response.
    $fields = array();
    foreach (explode(',', trim($edit['header'])) as $part) {
      if (!empty($part)) {
        list($key, $value) = explode('=', trim($part), 2);
        $fields[$key] = trim($value, '"');
      }
    }
    $uri = parse_url($edit['uri']);
    $field_uri = isset($fields['uri']) ? parse_url($fields['uri']) : NULL;
    $realm = isset($edit['srealm']) ? $edit['srealm'] : $fields['realm'];
    $securesite_nonce = db_fetch_array(db_query("SELECT qop, nc, opaque, hash FROM {securesite_nonce} WHERE nonce = '%s' AND realm = '%s'", $fields['nonce'], $realm));
    $required = array('username', 'realm', 'nonce', 'uri', 'response');
    $required = isset($fields['qop']) ? $required + array('cnonce', 'opaque', 'nc') : $required;
    if (
      // URI matches current page.
      $uri['path'] == $field_uri['path'] &&
      (
        // Quality of protection fields are valid.
        isset($fields['qop']) && ($securesite_nonce === FALSE || in_array($fields['qop'], explode(',', $securesite_nonce['qop'])) && $securesite_nonce['opaque'] == $fields['opaque']) ||
        !isset($fields['qop']) && !isset($fields['nc'])
      ) &&
      // Required fields are present.
      array_diff($required, array_keys($fields)) == array()
    ) {
      $pass = db_result(db_query("SELECT pass FROM {securesite_passwords} WHERE name = '%s' AND realm = '%s'", $fields['username'], $realm));
      if ($pass !== FALSE) {
        // Password exists for this user.
        $method = isset($edit['method']) ? $edit['method'] : 'AUTHENTICATE';
        $ha1 = md5("$fields[username]:$fields[realm]:$pass");
        if (isset($fields['qop'])) {
          // Generate digest with quality of protection.
          switch ($fields['qop']) {
            case 'auth-int':
              $ha2 = md5("$method:$fields[uri]:$securesite_nonce[hash]");
              break;
            case 'auth':
              $ha2 = md5("$method:$fields[uri]");
              break;
          }
          $digest = md5("$ha1:$fields[nonce]:$fields[nc]:$fields[cnonce]:$fields[qop]:$ha2");
          $dec_nc = hexdec($fields['nc']);
        }
        else {
          // Generate digest without quality of protection.
          $ha2 = md5("$method:$fields[uri]");
          $digest = md5("$ha1:$fields[nonce]:$ha2");
          $dec_nc = $securesite_nonce['nc'] + 1;
        }
        $max_nc = variable_get('securesite_max_nc', $dec_nc + 1);
        if (
          // Response is valid
          $digest == $fields['response'] &&
          // Nonce is expired.
          ($securesite_nonce === FALSE || isset($fields['qop']) && $dec_nc > $max_nc)
        ) {
          // Notify user that nonce is stale and request authentication with new nonce.
          db_query("DELETE FROM {securesite_nonce} WHERE nonce = '%s'", $fields['nonce']);
          $nonce = uniqid();
          $opaque = isset($fields['opaque']) ? $fields['opaque'] : base64_encode($nonce);
          $nonce_fields = array('nonce' => "'%s'", 'opaque' => "'%s'", 'time' => '%d', 'realm' => "'%s'");
          $nonce_values = array($nonce, $opaque, $time, $realm);
          $nonce_fields += array('qop' => "'%s'");
          $nonce_values += isset($securesite_nonce['qop']) ? array($securesite_nonce['qop']) : isset($fields['qop']) ? array($fields['qop']) : array('auth');
          $nonce_fields += isset($edit['entity-body']) ? array('hash' => "'%s'") : array();
          $nonce_values += isset($edit['entity-body']) ? array(md5($edit['entity-body'])) : array();
          db_query("INSERT INTO {securesite_nonce} (". implode(', ', array_keys($nonce_fields)) .") VALUES (". implode(', ', $nonce_fields) .")", $nonce_values);
          $output = 'WWW-Authenticate: Digest realm="'. $fields['realm'] .'", nonce="'. $nonce .'", opaque="'. $opaque .'", stale=true, qop="'. $securesite_nonce['qop'] .'"';
        }
        elseif (
          // Response is invalid.
          $digest != $fields['response'] ||
          isset($fields['qop']) && (
            // Replay attack detected.
            $dec_nc <= $securesite_nonce['nc'] ||
            // We don't have hash for last entity body.
            $fields['qop'] == 'auth-int' && $dec_nc != $securesite_nonce['nc'] + 1
          )
        ) {
          // Request re-authentication.
          $output = 'WWW-Authenticate: Digest realm="'. $fields['realm'] .'", nonce="'. $fields['nonce'] .'", opaque="'. $fields['opaque'] .'", qop="'. $securesite_nonce['qop'] .'"';
        }
        else {
          // Report successful authentication.
          $header = array();
          if ($dec_nc < $max_nc) {
            if (isset($hash)) {
              db_query("UPDATE {securesite_nonce} SET nc = %d, time = %d, hash = '%s' WHERE nonce = '%s'", $dec_nc, $time, $hash, $fields['nonce']);
            }
            else {
              db_query("UPDATE {securesite_nonce} SET nc = %d, time = %d, hash = NULL WHERE nonce = '%s'", $dec_nc, $time, $fields['nonce']);
            }
          }
          else {
            // Send next nonce if we have reached the maximum number of uses for this one.
            $nextnonce = uniqid();
            db_query("DELETE FROM {securesite_nonce} WHERE nonce = '%s'", $fields['nonce']);
            if (isset($hash)) {
              db_query("INSERT INTO {securesite_nonce} (nonce, time, hash) VALUES ('%s', %d, '%s')", $nextnonce, $time, $hash);
            }
            else {
              db_query("INSERT INTO {securesite_nonce} (nonce, time) VALUES ('%s', %d)", $nextnonce, $time);
            }
            $header[] = 'nextnonce="'. $nextnonce .'"';
          }
          if (isset($fields['qop'])) {
            $header[] = 'qop='. $fields['qop'];
            switch ($fields['qop']) {
              case 'auth-int':
                $header[] = 'cnonce="'. $fields['cnonce'] .'"';
                $header[] = 'nc="'. $fields['nc'] .'"';
                $ha2 = md5(":$fields[uri]:$hash");
                break;
              case 'auth':
                $header[] = 'cnonce="'. $fields['cnonce'] .'"';
                $header[] = 'nc='. $fields['nc'];
                $ha2 = md5(":$fields[uri]");
                break;
              default:
                $ha2 = md5(":$fields[uri]");
                break;
            }
            $digest = md5("$ha1:$fields[nonce]:$fields[nc]:$fields[cnonce]:$fields[qop]:$ha2");
          }
          else {
            $digest = md5("$ha1:$fields[nonce]:". md5(":$fields[uri]"));
          }
          $header[] = 'rspauth="'. $digest .'"';
          $output = 'Authentication-Info: '. implode(', ', $header);
        }
      }
      else {
        // Report unknown password.
        $output = 'unknown';
      }
    }
    else {
      // Report bad request.
      $output = 'HTTP/1.1 400 Bad Request';
    }
  }
  else {
    // Request authentication.
    $nonce = uniqid();
    $realm = isset($edit['srealm']) ? $edit['srealm'] : $edit['crealm'];
    $qop = isset($edit['qop']) ? $edit['qop'] : 'auth';
    $opaque = isset($edit['opaque']) ? $edit['opaque'] : base64_encode($nonce);
    if (isset($edit['entity-body'])) {
      db_query("INSERT INTO {securesite_nonce} (nonce, qop, opaque, time, realm, hash) VALUES ('%s', '%s', '%s', %d, '%s', '%s')", $nonce, $qop, $opaque, $time, $realm, md5($edit['entity-body']));
    }
    else {
      db_query("INSERT INTO {securesite_nonce} (nonce, qop, opaque, time, realm) VALUES ('%s', '%s', '%s', %d, '%s')", $nonce, $qop, $opaque, $time, $realm);
    }
    $output = 'WWW-Authenticate: Digest realm="'. $edit['crealm'] .'", nonce="'. $nonce .'", opaque="'. $opaque .'", qop="'. $qop .'"';
  }
  return $output;
}

