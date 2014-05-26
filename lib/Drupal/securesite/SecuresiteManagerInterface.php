<?php

/**
 * @file
 * Contains \Drupal\securesite\SecuresiteManagerInterface.
 */

namespace Drupal\securesite;

use Symfony\Component\HttpFoundation\Request;

/**
 * Defines an interface for managing securesite authentication
 */
interface SecuresiteManagerInterface {

  /**
   * Return the appropriate method of authentication for the request
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *  request for the page
   *
   * @return int
   *    type of the authentication mechanism
   */
  public function getMechanism(Request $request);

  /**
   * @param int $type
   *    type of the authentication mechanism
   */
  public function boot($type);
}