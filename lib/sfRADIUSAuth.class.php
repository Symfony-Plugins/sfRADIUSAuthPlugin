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
 * @link       www.symfony-project.org
 * @version    SVN: $Id $
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
	private $_radius;
	private $_chap;
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
	 * authenticate a username against a RADIUS server
	 *
	 * @param string $username username
	 * @param string $password password
	 *
	 * @return boolean
	 */
	public static function authenticateUser($username, $password)
	{
		$instance = self::getInstance();

		$type = sfConfig::get('app_sfRADIUSAuth_auth_type');
		$server = sfConfig::get('app_sfRADIUSAuth_server');
		$ports = sfConfig::get('app_sfRADIUSAuth_port');
		$secret = sfConfig::get('app_sfRADIUSAuth_secret');

		$class = 'Auth_RADIUS_'.$type;

		$radius = new $class($username, $password);

		switch ($type) {
		case 'MSCHAPv2':
			$radius->addServer($server, $ports['auth'], $secret);
			$radius->username = $username;

			$crpt = new Crypt_CHAP_MSv2();
			$crpt->password = $password;
			$crpt->username = $username;

			$radius->challenge = $crpt->authChallenge;
			$radius->peerChallenge = $crpt->peerChallenge;
			$radius->chapid = $crpt->chapid;
			$radius->response = $crpt->challengeResponse();

			break;
		case 'MSCHAPv1':
			throw new sfConfigurationException("Only MSCHAPv2 is supported atm.", 1);
			break;
		case 'PAP':
			throw new sfConfigurationException("Only MSCHAPv2 is supported atm.", 1);
			break;
		case 'CHAP_MD5':
			throw new sfConfigurationException("Only MSCHAPv2 is supported atm.", 1);
			break;
		}

		if (!$radius->start()) {
			throw new sfException($radius->getError());
			return false;
		}

		$result = $radius->send();
		if (PEAR::isError($result)) {
			$retval = false;
		} elseif ($result === true) {
			$retval = true;
		} else {
			$retval = false;
		}

		$radius->close();
		return $retval;
	}

	/**
	 * Singleton.
	 *
	 * @static
	 *
	 * @return void
	 */
	public static function getInstance()
	{
		if (self::$_instance !== null) {
			return self::$_instance;
		}

		self::$_instance = new sfRADIUSAuth();
		return self::$_instance;
	}
}