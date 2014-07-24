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
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
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

  // protected $authManager;

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
    $request = $event->getRequest();
    $this->manager->setRequest($request);

    //creating an array of headers to be added to the response. This array will be populated later on
    $request->securesiteHeaders = array();

    // Did the user send credentials that we accept?
    $type = $this->manager->getMechanism();
    var_dump($type);
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
        var_dump('showing dialog');
        $this->manager->showDialog(array_pop($types));
      }
    }
    var_dump('outside');
  }

  /**
   * Add headers to response based on authentication by securesite
   *
   * @param \Symfony\Component\HttpKernel\Event\FilterResponseEvent $event
   *   The event to process.
   */
  public function onResponse(FilterResponseEvent $event) {

    if ($event->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
      return;
    }

    $request = $event->getRequest();
    $response = $event->getResponse();
    foreach ($request->securesiteHeaders as $name => $value){
      $response->headers->set($name, $value);
    }

    //var_dump($response);
  }



  /**
   * Registers the methods in this class that should be listeners.
   *
   * @return array
   *   An array of event listener definitions.
   */
  static function getSubscribedEvents() {
    $events[KernelEvents::REQUEST][] = array('onKernelRequest', 0);
    $events[KernelEvents::RESPONSE][] = array('onResponse', 0);
    return $events;
  }

}
