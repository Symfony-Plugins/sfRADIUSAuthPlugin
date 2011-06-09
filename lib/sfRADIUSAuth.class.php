<?php
/**
 * RADIUS Auth plugin class for symfoyn
 *
 * PHP version 5
 *
 * @category   Symfony
 * @package    Plugins
 * @subpackage Auth
 * @author     BigBadBassMan <d.reiche@gmx.ch>
 * @license    http://www.symfony-project.org/license MIT
 * @version    SVN: $Id $
 * @link       www.symfony-project.org
 */

/**
 * RADIUS authentication class for symfony.
 *
 * @category   Symfony
 * @package    Plugins
 * @subpackage Auth
 * @author     BigBadBassMan <d.reiche@gmx.ch>
 * @license    http://www.symfony-project.org/license MIT
 * @link       www.symfony-project.org/plugins/sfRADIUSAuthPlugin
 */
class sfRADIUSAuth
{
  private static $_instance;


  /**
   * Constructor.
   *
   * @return sfRADIUSAuthPlugin
   */
  private function __construct()
  {


  }

  /**
   * Factory method to create a CRYPT object, based on type string.
   *
   * @param string $type crypt type to create.
   *
   * @return Crypt_CHAP
   */
  private static function _cryptFactory($type = 'MSCHAPv2')
  {
    $crypt = null;

    //create a class matching RADIUS server protocoll for encrypting traffic
    switch ($type) {
      case 'MSCHAPv1':
        $crypt = new Crypt_CHAP_MSv1();
        break;
      case 'MSCHAPv2':
        $crypt = new Crypt_CHAP_MSv2();
        break;
      case 'CHAP_MD5':
        $crypt = new Crypt_CHAP_MD5();
        break;
    }

    return $crypt;
  }

  /**
   * Factory method to create a radius object.
   *
   * @param string $type encryption type of radius to use.
   *
   * @throws InvalidArgumentException
   *
   * @return Auth_RADIUS
   */
  private static function _radiusFactory($type)
  {
    $radius = null;

    //set type of RADIUS server protocoll to use and create a matching class
    switch ($type) {
      case 'MSCHAPv1':
        $radius = new Auth_RADIUS_MSCHAPv1();
        break;
      case 'MSCHAPv2':
        $radius = new Auth_RADIUS_MSCHAPv2();
        break;
      case 'CHAP_MD5':
        $radius = new Auth_RADIUS_CHAP_MD5();
        break;
      case 'PAP':
        $radius = new Auth_RADIUS_PAP();
        break;
      default:
        throw new sfConfigurationException('only MSCHAPv1, MSCHAPv2, CHAP_MD5 and PAP are supported.', 1);
    }
    sfContext::getInstance()->getLogger()->info('authenticating to RADIUS via '.$type);
    return $radius;
  }

  /**
   * populate the server qeue of a RADIUS object with configured entries.
   *
   * @param Auth_RADIUS &$radius radius object to populate with server
   *
   * @return void
   */
  private static function _setTargetServers(Auth_RADIUS &$radius)
  {
  	//get config options
    $serverQeue = sfConfig::get('app_sfRADIUSAuth_server_qeue', false);
    $servers = sfConfig::get('app_sfRADIUSAuth_servers', null);

    sfContext::getInstance()->getLogger()->debug(print_r($servers, true));

    //if no servers are configured raise exception
    if (!is_array($servers) || count($servers) == 0)
    {
    	throw new sfConfigurationException('RADIUS server(s) must be configured properly!', 500);
    }

    //if in qeue mode, add all servers to radius list
    //if only one server was configured use this path to to prevent using costly
    //random function
    if ($serverQeue || count($servers)==1)
    {
      foreach ($servers as $server)
      {
      	if (isset($server['ip']) && isset($server['ports']['auth']) && isset($server['secret']))
      	{
      		$radius->addServer($server['ip'], $server['ports']['auth'], $server['secret']);
      		sfContext::getInstance()->getLogger()->info('using RADIUS server '.$server['ip'].' in qeued mode');
      	}
      	else
      	{
      	  sfContext::getInstance()->getLogger()->warning('RADIUS Server not configured properly in: '.print_r($server, true));
      	}
      }
    }
    // if not qeueing and more than one servers were defined, choose a random one.
    else
    {
      $key = array_rand($servers);

      $radius->addServer(
        $servers[$key]['ip'],
        $servers[$key]['ports']['auth'],
        $servers[$key]['secret']
      );

      sfContext::getInstance()->getLogger()->info('using random RADIUS server: '.$servers[$key]['ip']);
    }
  }

  /**
   * authenticate a username against a RADIUS server
   *
   * @param string $username username
   * @param string $password password
   *
   * @return boolean
   */
  public static function authenticateUser($username, $password, BasesfGuardUser $guardUser)
  {
  	//get configured RADIUS protocoll type
    $type = sfConfig::get('app_sfRADIUSAuth_auth_type');

    //create radius class name and pear object.
    $class = 'Auth_RADIUS_'.$type;
    $pear = new PEAR();

    //create radius object and populate username and password
    $radius = self::_radiusFactory($type);
    $radius->username = $username;
    $radius->password = $password;

    //set servers
    self::_setTargetServers($radius);

    $crypt = self::_cryptFactory($type);

    //configure radius object and connect to crypt class according to used protocol type
    switch ($type) {
      case 'MSCHAPv2':
        $radius->username = $username;

        $crypt->password = $password;
        $crypt->username = $username;

        $radius->challenge = $crypt->authChallenge;
        $radius->peerChallenge = $crypt->peerChallenge;
        $radius->chapid = $crypt->chapid;
        $radius->response = $crypt->challengeResponse();
        break;

      case 'CHAP_MD5':
      case 'MSCHAPv1':
        $crypt->password = $password;
        $radius->challenge = $crypt->challenge;
        $radius->chapid = $crypt->chapid;
        $radius->response = $crypt->challengeResponse();
        $radius->flags = 1;
        break;

      case 'PAP':
        $radius->password = $password;
        break;

      //something was misconfigured if we are here
      default:
        throw new sfConfigurationException('wrong RADIUS type supplied.', 1);
    }

    //start radius connection, only fails on wrong config or network downtime
    if (!$radius->start())
    {
      sfContext::getInstance()->getLogger()->crit('RADIUS auth not possible, check config and network!');
      sfContext::getInstance()->getLogger()->debug($radius->getError());
      return $guardUser->checkPasswordByGuard($password);
    }

    //send username/password and check result
    $result = $radius->send();
    if ($pear->isError($result))
    {
      sfContext::getInstance()->getLogger()->debug($radius->getError());
      sfContext::getInstance()->getLogger()->err('RADIUS auth failed, unexpected response from server.');
      $retval = false;
    }
    else if ($result === true)
    {
      $retval = true;
    }
    else
    {
      $retval = false;
    }

    $radius->close();
    return $retval;
  }
}