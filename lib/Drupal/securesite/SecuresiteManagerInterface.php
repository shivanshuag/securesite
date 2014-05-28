<?php

/**
 * @file
 * Contains \Drupal\securesite\SecuresiteManagerInterface.
 */

namespace Drupal\securesite;

use Symfony\Component\HttpFoundation\Request;
use Drupal\Core\Authentication\AuthenticationManager;

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
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *  request for the page
   *
   * @param \Drupal\Core\Authentication\AuthenticationManager $authManager
   */
  public function boot($type, Request $request, AuthenticationManager $authManager);

  public function showDialog($type, Request $request);

  public function forcedAuth();
}