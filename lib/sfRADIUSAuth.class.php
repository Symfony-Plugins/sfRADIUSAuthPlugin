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
			throw new InvalidArgumentException('only MSCHAPv1, MSCHAPv2, CHAP_MD5 and PAP are supported.', 1);
		}

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
		$serverQeue = sfConfig::get('app_sfRADIUSAuth_server_qeue');
		$servers = sfConfig::get('app_sfRADIUSAuth_servers');

		sfContext::getInstance()->getLogger()->debug(print_r($servers, true));

		if ($serverQeue || count($servers)==1) {
			foreach ($servers as $server) {
				$radius->addServer($server['ip'], $server['ports']['auth'], $server['secret']);
			}
		} else {
			$key = array_rand($servers);

			$radius->addServer(
				$servers[$key]['ip'],
				$servers[$key]['ports']['auth'],
				$servers[$key]['secret']
			);
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
	public static function authenticateUser($username, $password)
	{
		$type = sfConfig::get('app_sfRADIUSAuth_auth_type');

		$class = 'Auth_RADIUS_'.$type;

		$radius = self::_radiusFactory($type);
		$radius->username = $username;
		$radius->password = $password;

		self::_setTargetServers($radius);

		$crypt = self::_cryptFactory($type);

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
		default:
			throw new sfConfigurationException('wrong RADIUS type supplied.', 1);
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
}