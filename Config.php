<?php
/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */
namespace Piwik\Plugins\LoginLdap;

use Exception;
use Piwik\Config as PiwikConfig;
use Piwik\Container\StaticContainer;
use Piwik\Plugins\LoginLdap\Ldap\Client;
use Piwik\Plugins\LoginLdap\Ldap\ServerInfo;
use Psr\Log\LoggerInterface;
use Piwik\Plugins\SitesManager\API as SitesManagerApi;

/**
 * Utility class with methods to manage LoginLdap INI configuration.
 */
class Config
{
    const ENTITLEMENTS_KEY_PREFIX = 'entitlements_site_';
    const ADMIN_KEY_SUFFIX = '_admin_dn';
    const VIEW_KEY_SUFFIX = '_view_dn';

    public static $defaultConfig = array(
        'use_ldap_for_authentication' => 1,
        'synchronize_users_after_login' => 1,
        'enable_synchronize_access_from_ldap' => 0,
        'new_user_default_sites_view_access' => '',
        'user_email_suffix' => '',
        'append_user_email_suffix_to_username' => 1,
        'required_member_of' => '',
        'required_member_of_field' => 'memberOf',
        'ldap_user_filter' => '',
        'ldap_user_id_field' => 'uid',
        'ldap_last_name_field' => 'sn',
        'ldap_first_name_field' => 'givenName',
        'ldap_alias_field' => 'cn',
        'ldap_mail_field' => 'mail',
        'ldap_password_field' => 'userPassword',
        'ldap_view_access_field' => 'view',
        'ldap_admin_access_field' => 'admin',
        'ldap_superuser_access_field' => 'superuser',
        'use_webserver_auth' => 0,
        'user_access_attribute_server_specification_delimiter' => ';',
        'user_access_attribute_server_separator' => ':',
        'instance_name' => '',
        'ldap_network_timeout' => Client::DEFAULT_TIMEOUT_SECS,
        'entitlements_type' => 'attributes',
        'entitlements_superuser_dn'=> ''
    );

    // for backwards compatibility
    public static $alternateOptionNames = array(
        'user_email_suffix' => array('usernameSuffix'),
        'required_member_of' => array('memberOf'),
        'ldap_user_filter' => array('filter'),
        'ldap_user_id_field' => array('userIdField'),
        'ldap_alias_field' => array('aliasField'),
        'ldap_mail_field' => array('mailField'),
        'use_webserver_auth' => array('useKerberos'),
    );

    /**
     * Returns an INI option value that is stored in the `[LoginLdap]` config section.
     *
     * If alternate option names exist for the option name, they will be used as fallbacks.
     *
     * @param $optionName
     * @return mixed
     */
    public static function getConfigOption($optionName)
    {
        return self::getConfigOptionFrom(PiwikConfig::getInstance()->LoginLdap, $optionName);
    }

    public static function getConfigOptionFrom($config, $optionName)
    {
        if (isset($config[$optionName])) {
            return $config[$optionName];
        } else if (isset(self::$alternateOptionNames[$optionName])) {
            foreach (self::$alternateOptionNames[$optionName] as $alternateName) {
                if (isset($config[$alternateName])) {
                    return $config[$alternateName];
                }
            }
            return self::getDefaultConfigOptionValue($optionName);
        } else {
            return self::getDefaultConfigOptionValue($optionName);
        }
    }

    public static function getDefaultConfigOptionValue($optionName)
    {
        return @self::$defaultConfig[$optionName];
    }

    public static function isAccessSynchronizationEnabled()
    {
        return self::getConfigOption('enable_synchronize_access_from_ldap');
    }

    public static function getDefaultSitesToGiveViewAccessTo()
    {
        return self::getConfigOption('new_user_default_sites_view_access');
    }

    public static function getRequiredMemberOf()
    {
        return self::getConfigOption('required_member_of');
    }

    public static function getRequiredMemberOfField()
    {
        return self::getConfigOption('required_member_of_field');
    }

    public static function getLdapUserFilter()
    {
        return self::getConfigOption('ldap_user_filter');
    }

    public static function getLdapUserIdField()
    {
        return self::getConfigOption('ldap_user_id_field');
    }

    public static function getLdapLastNameField()
    {
        return self::getConfigOption('ldap_last_name_field');
    }

    public static function getLdapFirstNameField()
    {
        return self::getConfigOption('ldap_first_name_field');
    }

    public static function getLdapAliasField()
    {
        return self::getConfigOption('ldap_alias_field');
    }

    public static function getLdapMailField()
    {
        return self::getConfigOption('ldap_mail_field');
    }

    public static function getLdapPasswordField()
    {
        return self::getConfigOption('ldap_password_field');
    }

    public static function getLdapUserEmailSuffix()
    {
        return self::getConfigOption('user_email_suffix');
    }

    public static function getLdapViewAccessField()
    {
        return self::getConfigOption('ldap_view_access_field');
    }

    public static function getLdapAdminAccessField()
    {
        return self::getConfigOption('ldap_admin_access_field');
    }

    public static function getSuperUserAccessField()
    {
        return self::getConfigOption('ldap_superuser_access_field');
    }

    public static function shouldUseWebServerAuthentication()
    {
        return self::getConfigOption('use_webserver_auth') == 1;
    }

    public static function getUserAccessAttributeServerSpecificationDelimiter()
    {
        return self::getConfigOption('user_access_attribute_server_specification_delimiter');
    }

    public static function getUserAccessAttributeServerSiteListSeparator()
    {
        return self::getConfigOption('user_access_attribute_server_separator');
    }

    public static function getDesignatedPiwikInstanceName()
    {
        return self::getConfigOption('instance_name');
    }

    public static function getUseLdapForAuthentication()
    {
        return self::getConfigOption('use_ldap_for_authentication') == 1;
    }

    public static function getShouldSynchronizeUsersAfterLogin()
    {
        return self::getConfigOption('synchronize_users_after_login') == 1;
    }

    public static function getLdapNetworkTimeout()
    {
        return self::getConfigOption('ldap_network_timeout');
    }

    public static function shouldAppendUserEmailSuffixToUsername()
    {
        return self::getConfigOption('append_user_email_suffix_to_username') == 1;
    }

    public static function getEntitlementsType()
    {
        return self::getConfigOption('entitlements_type');
    }

    public static function getEntitlementsSuperuserDN()
    {
        return self::getConfigOption('entitlements_superuser_dn');
    }

    public static function getServerConfig($server)
    {
        $configName = 'LoginLdap_' . $server;
        return PiwikConfig::getInstance()->__get($configName);
    }

    public static function getServerNameList()
    {
        return self::getConfigOption('servers');
    }

    public static function getGroupEntitlements()
    {
        $loginLdap = PiwikConfig::getInstance()->LoginLdap;
        $entitlementsKeys = array_filter(array_keys($loginLdap), function($el) {
            return strpos($el, self::ENTITLEMENTS_KEY_PREFIX) === 0;
        });
        $result = array();
        foreach($entitlementsKeys as $entitlementsKey) {
            $result[$entitlementsKey] = $loginLdap[$entitlementsKey];
        }
        return $result;
    }

    public static function getGroupEntitlementsSuperuser()
    {
        $loginLdap = PiwikConfig::getInstance()->LoginLdap;
        $potential_keys = array();
        $result = array();
        $api = SitesManagerApi::getInstance();
        $allSites = $api->getAllSites();
        foreach($allSites as $site) {
            $potential_keys[] = self::ENTITLEMENTS_KEY_PREFIX . $site['idsite'] . self::ADMIN_KEY_SUFFIX;
            $potential_keys[] = self::ENTITLEMENTS_KEY_PREFIX . $site['idsite'] . self::VIEW_KEY_SUFFIX;
        }
        foreach($potential_keys as $pk) {
            $result[$pk] = self::getConfigOption($pk);
        }
        return $result;
    }

    /**
     * Returns a list of {@link ServerInfo} instances describing the LDAP servers
     * that should be connected to.
     *
     * @return ServerInfo[]
     */
    public static function getConfiguredLdapServers()
    {
        $serverNameList = self::getServerNameList();

        if (empty($serverNameList)) {
            $server = ServerInfo::makeFromOldConfig();
            $serverHost = $server->getServerHostname();

            if (empty($serverHost)) {
                return array();
            } else {
                return array($server);
            }
        } else {
            if (is_string($serverNameList)) {
                $serverNameList = explode(',', $serverNameList);
            }

            $servers = array();
            foreach ($serverNameList as $name) {
                try {
                    $servers[] = ServerInfo::makeConfigured($name);
                } catch (Exception $ex) {
                    /** @var LoggerInterface */
                    $logger = StaticContainer::get('Psr\Log\LoggerInterface');

                    $logger->debug("LoginLdap\\Config::{func}: LDAP server info '{name}' is configured incorrectly: {message}", array(
                        'func' => __FUNCTION__,
                        'name' => $name,
                        'message' => $ex->getMessage(),
                        'exception' => $ex
                    ));
                }
            }
            return $servers;
        }
    }

    public static function getPluginOptionValuesWithDefaults()
    {
        $result = self::$defaultConfig;
        foreach ($result as $name => $ignore) {
            $actualValue = Config::getConfigOption($name);

            // special check for useKerberos which can be a string
            if ($name == 'use_webserver_auth'
                && $actualValue === 'false'
            ) {
                $actualValue = 0;
            }

            if (isset($actualValue)) {
                $result[$name] = $actualValue;
            }
        }
        return $result;
    }

    public static function savePluginOptions($config)
    {
        $loginLdap = PiwikConfig::getInstance()->LoginLdap;

        foreach (self::$defaultConfig as $name => $value) {
            if (isset($config[$name])) {
                $loginLdap[$name] = $config[$name];
            }
        }

        PiwikConfig::getInstance()->LoginLdap = $loginLdap;
        PiwikConfig::getInstance()->forceSave();
    }

    public static function saveGroupEntitlements($config) {
        $loginLdap = PiwikConfig::getInstance()->LoginLdap;
        $api = SitesManagerApi::getInstance();

        // construct the list of all sites' entitlements keys
        $siteIds = array_keys($api->getAllSites());
        $entitlementsKeys = array();
        foreach($siteIds as $siteId) {
            $entitlementsKeys[] = self::ENTITLEMENTS_KEY_PREFIX . $siteId . self::ADMIN_KEY_SUFFIX;
            $entitlementsKeys[] = self::ENTITLEMENTS_KEY_PREFIX . $siteId . self::VIEW_KEY_SUFFIX;
        }

        // persist the entitlements
        foreach ($entitlementsKeys as $key) {
            if (isset($config[$key])) {
                $loginLdap[$key] = $config[$key];
            }
        }
        PiwikConfig::getInstance()->LoginLdap = $loginLdap;
        PiwikConfig::getInstance()->forceSave();
    }

    public static function saveLdapServerConfigs($servers)
    {
        $serverNames = array();
        foreach ($servers as $serverInfo) {
            ServerInfo::saveServerConfig($serverInfo, $forceSave = false);

            $serverNames[] = $serverInfo['name'];
        }
        PiwikConfig::getInstance()->LoginLdap['servers']= $serverNames;

        PiwikConfig::getInstance()->forceSave();
    }
}