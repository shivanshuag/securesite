<?php

/**
 * @file
 * Contains Drupal\securesite\EventSubscriber\SecuresiteSubscriber.
 */

namespace Drupal\securesite\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Drupal\securesite\SecuresiteManagerInterface;

/**
 * Subscribes to the kernel request event to check whether authentication is required
 */
class SecuresiteSubscriber implements EventSubscriberInterface {

  /**
   * The manager used to check for authentication.
   *
   * @var \Drupal\securesite\SecuresiteManagerInterface
   */
  protected $manager;

  protected $authManager;

  /**
   * Construct the SecuresiteSubscriber.
   *
   * @param \Drupal\securesite\SecuresiteManagerInterface $manager
   *   The manager used to check for authentication.
   */

  public function __construct(SecuresiteManagerInterface $manager){
    $this->manager = $manager;
  }

  /**
   * Check every page request for authentication
   *
   * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
   *   The event to process.
   */
  public function onKernelRequest(GetResponseEvent $event) {
    $account = \Drupal::currentUser();
    $this->manager->setRequest($event->getRequest());

    // Did the user send credentials that we accept?
    $type = $this->manager->getMechanism();
    if ($type !== FALSE && (isset($_SESSION['securesite_repeat']) ? !$_SESSION['securesite_repeat'] : TRUE)) {
      $this->manager->boot($type);
    }
    // If credentials are missing and user is not logged in, request new credentials.
    elseif ($account->id() == 0 && !isset($_SESSION['securesite_guest'])) {
      if (isset($_SESSION['securesite_repeat'])) {
        unset($_SESSION['securesite_repeat']);
      }
      if ($this->manager->forcedAuth()) {
        $types = \Drupal::config('securesite.settings')->get('securesite_type');
        sort($types, SORT_NUMERIC);
        $this->manager->showDialog(array_pop($types));
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
    $events[KernelEvents::REQUEST][] = array('onKernelRequest', 0);
    return $events;
  }

}
