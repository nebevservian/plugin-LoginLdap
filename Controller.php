<?php
/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */
namespace Piwik\Plugins\LoginLdap;

use Exception;
use Piwik\Nonce;
use Piwik\Notification;
use Piwik\Option;
use Piwik\Piwik;
use Piwik\Plugin\ControllerAdmin;
use Piwik\Plugin\Manager as PluginManager;
use Piwik\Plugins\LoginLdap\Ldap\ServerInfo;
use Piwik\Session;
use Piwik\View;
use Piwik\Plugins\SitesManager\API as SitesManagerApi;

/**
 * Login controller
 *
 * @package Login
 */
class Controller extends \Piwik\Plugins\Login\Controller
{
    /**
     * @return string
     */
    public function admin()
    {
        Piwik::checkUserHasSuperUserAccess();
        $view = new View('@LoginLdap/index');

        ControllerAdmin::setBasicVariablesAdminView($view);

        if (!function_exists('ldap_connect')) {
            $notification = new Notification(Piwik::translate('LoginLdap_LdapFunctionsMissing'));
            $notification->context = Notification::CONTEXT_ERROR;
            $notification->type = Notification::TYPE_TRANSIENT;
            $notification->flags = 0;
            Notification\Manager::notify('LoginLdap_LdapFunctionsMissing', $notification);
        }

        $this->setBasicVariablesView($view);

        $serverNames = Config::getServerNameList() ?: array();

        $view->servers = array();
        if (empty($serverNames)) {
            try {
                $serverInfo = ServerInfo::makeFromOldConfig()->getProperties();
                $serverInfo['name'] = 'server';
                $view->servers[] = $serverInfo;
            } catch (Exception $ex) {
                // ignore
            }
        } else {
            foreach ($serverNames as $server) {
                $serverConfig = Config::getServerConfig($server);
                if (!empty($serverConfig)) {
                    $serverConfig['name'] = $server;
                    $view->servers[] = $serverConfig;
                }
            }
        }

        // Pass list of sites to the view
        $api = SitesManagerApi::getInstance();
        $allSites = $api->getAllSites();
        $view->allSites = $allSites;

        // remove password field
        foreach ($view->servers as &$serverInfo) {
            unset($serverInfo['admin_pass']);
        }

        $view->ldapConfig = Config::getPluginOptionValuesWithDefaults();
        $view->ldapConfig['groupEntitlements'] = Config::getGroupEntitlementsSuperuser(); // Get Group Entitlements (as superuser)


        $view->isLoginControllerActivated = PluginManager::getInstance()->isPluginActivated('Login');

        $view->updatedFromPre30 = Option::get('LoginLdap_updatedFromPre3_0');

        $view->exampleGroupDn = 'cn=Admin Group,ou=Users,dc=organization,dc=com';
        $view->exampleUserDn = 'cn=Piwik User,ou=Users,dc=organization,dc=com';
        $view->exampleBaseDn = 'dc=organization,dc=com';

        return $view->render();
    }
}