<?php
/**
 * Config file for sfRADIUSAuthPlugin
 *
 * PHP version 5
 *
 * @category   Symfony
 * @package    Plugins
 * @subpackage Auth
 * @author     BigBadBassMan <d.reiche@gmx.ch>
 * @license    http://www.symfony-project.org/license MIT
 * @version    SVN: $Id$
 * @link       www.symfony-project.org
 */

/**
 * Config class for sfRADIUSAuthPlugin
 *
 * @category   Symfony
 * @package    Plugins
 * @subpackage Auth
 * @author     BigBadBassMan <d.reiche@gmx.ch>
 * @license    http://www.symfony-project.org/license MIT
 * @release    0.1.1
 * @link       www.symfony-project.org/plugins/sfRADIUSAuthPlugin
 * @see        sfPluginConfiguration
 */
class sfRADIUSAuthPluginConfiguration extends sfPluginConfiguration
{
  /**
   * init method
   *
   * @see sfPluginConfiguration::initialize()
   *
   * @return void
   */
  public function initialize()
  {
    if (!sfConfig::get('settings_sfRADIUSAuth_enabled', false))
    {
      return;
    }

    if (in_array('sfGuardAuth', sfConfig::get('sf_enabled_modules', array())))
    {
      sfConfig::set(
        'app_sf_guard_plugin_check_password_callable',
        array('sfRADIUSAuth', 'authenticateUser')
      );
    }
  }

  /**
   * initAutoload
   *
   * @see sfPluginConfiguration::initializeAutoload()
   *
   * @return void
   */
  public function initializeAutoload()
  {


    parent::initializeAutoload();
  }
}