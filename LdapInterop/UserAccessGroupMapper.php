<?php
namespace Piwik\Plugins\LoginLdap\LdapInterop;

use Piwik\Access;
use Piwik\Container\StaticContainer;
use Piwik\Plugins\LoginLdap\Config;
use Piwik\Plugins\SitesManager\API as SitesManagerAPI;
use Psr\Log\LoggerInterface;
use Piwik\Plugins\LoginLdap\LdapInterop\UserAccessMapper;
use Piwik\Plugins\LoginLdap\Model\LdapUsers;

class UserAccessGroupMapper extends UserAccessMapper
{
    const SU_ACCESS = 'superuser';
    const ADMIN_ACCESS = 'admin';
    const VIEW_ACCESS = 'view';

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * An array with each element being a sub array with group_dn, site_id (optional) and access_level (superuser, admin or view)
     * @var array
     */
    private $groupPermissions;

    private function addGroupPermission($groupDn, $accessLevel, $siteId = null)
    {
        if (strlen(trim($groupDn)) === 0) {
            return;
        }
        $groupPermission = array(
            'group_dn' => $groupDn,
            'access_level' => $accessLevel,
        );
        if (!is_null($siteId) && is_numeric($siteId)) {
            $groupPermission['site_id'] = $siteId;
        }
        $this->groupPermissions[] = $groupPermission;
        $this->logger->debug("UserAccessGroupMapper::{func}(): Users in {group_dn} will be {access_level} for {site}", array(
            'func' => __FUNCTION__,
            'group_dn' => $groupDn,
            'access_level' => $accessLevel . 's',
            'site' => is_null($siteId) ? 'All sites' : 'Site ID $siteId'
        ));
    }

    /**
     * Returns an array describing an LDAP user's access to Piwik sites.
     *
     * The array will either mark the user as a superuser, in which case it will look like
     * this:
     *
     *     array('superuser' => true)
     *
     * Or it will map user access levels with lists of site IDs, for example:
     *
     *     array(
     *         'view' => array(1,2,3),
     *         'admin' => array(3,4,5)
     *     )
     *
     * @param string[] $ldapUser The LDAP entity information.
     * @return array
     */
    public function getPiwikUserAccessForLdapUser($ldapUser)
    {
        $this->logger->debug("UserAccessGroupMapper::{func}(): Preparing to look through all potential groups. {permissions}", array(
            'func' => __FUNCTION__,
            'permissions' => print_r($this->groupPermissions, true)
        ));

        // Get the Ldap Connection in case we need to search
        $ldapClient = LdapUsers::makeConfigured();

        // Make sure that the groups are an array. This can be an issue when user has only 1 group
        if (!is_array($ldapUser[strtolower($memberOfAttribute)])) {
                $ldapUser[strtolower($memberOfAttribute)] = array( $ldapUser[strtolower($memberOfAttribute)] );
        }

        // Direct memberships are easier to resolve against (ie. 'memberOf' in AD)
        $memberOfAttribute = Config::getRequiredMemberOfField();
        $directMemberships = array();
        if (array_key_exists(strtolower($memberOfAttribute), $ldapUser)) {
            $directMemberships = array_map(function($tmp_dn) {
                return strtolower($tmp_dn);
            }, $ldapUser[strtolower($memberOfAttribute)]);
        }

        $this->logger->debug("UserAccessGroupMapper::{func}(): Direct Memberships: {memberships}", array(
            'func' => __FUNCTION__,
            'memberships' => print_r($directMemberships, true)
        ));

        $result = array();

        // For each possible group permissions, check if this user should be granted the permission and at what level.
        foreach($this->groupPermissions as $groupPermission) {
            // Check Direct membership first
            $this->logger->debug("UserAccessGroupMapper::{func}(): Checking to see if user is a member of {group}", array(
                'func' => __FUNCTION__,
                'group' => $groupPermission['group_dn']
            ));
            $isGroupMember = in_array(strtolower($groupPermission['group_dn']), $directMemberships);

            if ($isGroupMember === false) {
                // If it's AD, we can do a recursive search up the group hierarchy.
                $isGroupMember = $this->userExistsRecursive($ldapClient, $ldapUser['dn'], $groupPermission['group_dn']);
            }

            if ($isGroupMember === true) {
                // Check for super user access - if found then we're done
                if ($groupPermission['access_level'] === self::SU_ACCESS) {
                    $result = array(self::SU_ACCESS => true);
                    self::logFinalPermissionResult($ldapUser['dn'], $result);
                    return $result;
                }

                // Check for admin access
                if ($groupPermission['access_level'] === self::ADMIN_ACCESS) {
                    if (array_key_exists(self::ADMIN_ACCESS, $result) === false) {
                        $result[self::ADMIN_ACCESS] = array();
                    }
                    $result[self::ADMIN_ACCESS][] = $groupPermission['site_id'];
                }

                // Check for view access
                if ($groupPermission['access_level'] === self::VIEW_ACCESS) {
                    // Only want to add view access if admin access has not already been granted for the site
                    if (array_key_exists(self::ADMIN_ACCESS, $result) === false ||
                        in_array($groupPermission['site_id'], $result[self::ADMIN_ACCESS]) === false)
                    {
                        if (array_key_exists(self::VIEW_ACCESS, $result) === false) {
                            $result[self::VIEW_ACCESS] = array();
                        }
                        $result[self::VIEW_ACCESS][] = $groupPermission['site_id'];
                    }
                }
            }
        }

        self::logFinalPermissionResult($ldapUser['dn'], $result);
        return $result;
    }

    protected function userExistsRecursive($ldapClient, $userDn, $groupDn)
    {
        $userDnExploded = explode(',', $userDn);
        $userCn = substr($userDnExploded[0], 3); 
        $this->logger->debug("UserAccessGroupMapper::{func}(): Checking to see if {userCn} exists in {groupDn} (recursively)", array(
            'func' => __FUNCTION__,
            'userCn' => $userCn,
            'groupDn' => $groupDn
        ));

        // Constructs the extremely magic AD recursive search string.
        // Yes. Dodgy as hell, but cannot use "use".
        $ldapClient->tmpSearchString = "(&(objectCategory=Person)(cn=". $userCn .")(memberOf:1.2.840.113556.1.4.1941:=". $groupDn ."))";
        $searchResult = $ldapClient->doWithClient(function($ldapUsers, $tmpLdapClient, $serverInfo) {

            $baseDn = $serverInfo->getBaseDn();
            $ldapUsers->bindAsAdmin($tmpLdapClient, $serverInfo);

            $results = $tmpLdapClient->fetchAll(
                $baseDn,
                $ldapUsers->tmpSearchString,
                array(),
                array('dn')
            );
            return $results;
        });

        if (is_null($searchResult) === false && sizeof($searchResult) > 0) {
            foreach($searchResult as $sr) {
                if (strtolower($sr['dn']) === strtolower($userDn)) {
                    $this->logger->debug('UserAccessGroupMapper::{func}(): FOUND {userCn} in {groupDn}', array(
                        'userCn' => $userCn,
                        'groupDn' => $groupDn
                    ));
                    return true;
                }
            }
        }

        $this->logger->debug('UserAccessGroupMapper::{func}(): {userCn} could not be found in {groupDn}', array(
            'userCn' => $userCn,
            'groupDn' => $groupDn
        ));
        return false;
    }

    /**
     * Constructor.
     */
    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger ?: StaticContainer::get('Psr\Log\LoggerInterface');
    }

    public static function makeConfigured() {
        $result = new self();

        // Get the Superuser group DN first
        $result->addGroupPermission(Config::getEntitlementsSuperuserDN(), self::SU_ACCESS);

        // Get Group DNs
        $siteDNs = Config::getGroupEntitlements();
        $entitlements = array();
        foreach($siteDNs as $entitlementDescriptor => $entitlementDn) {
            $entitlementInfo = explode('_', $entitlementDescriptor);
            $entitlements[] = array(
                'site_id' => $entitlementInfo[2],
                'access_level' => $entitlementInfo[3],
                'entitlement_dn' => $entitlementDn
            );
        }

        $result->addGroupPermissionForAccessLevel($entitlements, self::ADMIN_ACCESS);
        $result->addGroupPermissionForAccessLevel($entitlements, self::VIEW_ACCESS);

        return $result;
    }

    private function addGroupPermissionForAccessLevel($allEntitlements, $accessLevel) {
        $entitlements = array_filter($allEntitlements, function ($el) use($accessLevel) {
            return $el['access_level'] === $accessLevel;
        });
        forEach($entitlements as $entitlement) {
            $this->addGroupPermission($entitlement['entitlement_dn'], $accessLevel, $entitlement['site_id']);
        }
    }

    private function logFinalPermissionResult($userDn, $result) {
        $this->logger->debug('**** Final permissions for {userDn} are:', array('userDn' => $userDn));
        $this->logger->debug(print_r($result, true));
    }
}