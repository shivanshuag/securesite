<?php

/**
 * @file
 * Contains Drupal\securesite\EventSubscriber\SecuresiteSubscriber.
 */

namespace Drupal\securesite\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Subscribes to the kernel request event to check whether authentication is required
 */
class SecuresiteSubscriber implements EventSubscriberInterface {

  /**
   *
   *
   * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
   *   The event to process.
   */
  public function onKernelRequest(GetResponseEvent $event) {
    global $user;
    // Did the user send credentials that we accept?
    $type = _securesite_mechanism();
    if ($type !== FALSE && (isset($_SESSION['securesite_repeat']) ? !$_SESSION['securesite_repeat'] : TRUE)) {
      drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
      module_load_include('inc', 'securesite');
      _securesite_boot($type);
    }
    // If credentials are missing and user is not logged in, request new credentials.
    elseif (empty($user->uid) && !isset($_SESSION['securesite_guest'])) {
      if (isset($_SESSION['securesite_repeat'])) {
        unset($_SESSION['securesite_repeat']);
      }
      $types = \Drupal::config('securesite.settings')->get('securesite_type');
      sort($types, SORT_NUMERIC);
      drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
      module_load_include('inc', 'securesite');
      if (_securesite_forced()) {
        _securesite_dialog(array_pop($types));
      }
    }
  }

  /**
   * Registers the methods in this class that should be listeners.
   *
   * @return array
   *   An array of event listener definitions.
   */
  static function getSubscribedEvents() {
    $events[KernelEvents::REQUEST][] = array('onKernelRequest', 40);
    return $events;
  }

}
