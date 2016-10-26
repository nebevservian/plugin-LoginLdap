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

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * An array with each element being a sub array with group_dn, site_id (optional) and access_level (superuser, admin or view)
     * @var array
     */
    private $groupsPermission;

    private function addPotentialGroupPermission($groupDn, $accessLevel, $siteId = null)
    {
        $tmpGrp = array(
            'group_dn' => $groupDn,
            'access_level' => $accessLevel,
        );
        if (!is_null($siteId) && is_numeric($siteId)) {
            $tmpGrp['site_id'] = $siteId;
        }
        $this->groupsPermission[] = $tmpGrp;
        /*$this->logger->debug("UserAccessGroupMapper::{func}(): Users in {group_dn} will be {access_level} for {site}", array(
            'func' => __FUNCTION__,
            'group_dn' => $groupDn,
            'access_level' => $accessLevel . "s",
            'site' => is_null($siteId) ? "All sites" : "Site ID $siteId"
        ));
        */
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
        $this->logger->debug("UserAccessGroupMapper::{func}(): Preparing to look through all potential groups.", array(
            'func' => __FUNCTION__
        ));

        // Get the Ldap Connection in case we need to search
        $ldapClient = LdapUsers::makeConfigured();

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

        // Loop through all the group checks
        foreach( $this->groupsPermission as $permissionDirective ) {
            // Check Direct membership first
            $this->logger->debug("UserAccessGroupMapper::{func}(): Checking to see if user is a member of {group}", array(
                "func" => __FUNCTION__,
                "group" => $permissionDirective['group_dn']
            ));
            $isGroupMember = in_array( strtolower($permissionDirective['group_dn']), $directMemberships );

            if ($isGroupMember === false) {
                // If it's AD, we can do a recursive search
                $isGroupMember = $this->userExistsRecursive($ldapClient, $ldapUser['dn'], $permissionDirective['group_dn']);
            }

            if ($isGroupMember === true) {

                if ($permissionDirective['access_level'] === 'superuser') {
                    return array('superuser' => true);
                }

                if ($permissionDirective['access_level'] === 'admin') {
                    if (array_key_exists('admin', $result) === false) {
                        $result['admin'] = array();
                    }
                    $result['admin'][] = $permissionDirective['site_id'];
                }

                if ($permissionDirective['access_level'] === 'view') {
                    // ensure we haven't already added this site as an admin
                    if (in_array($permissionDirective['site_id'], $result['admin']) === false) {
                        if (array_key_exists('view', $result) === false) {
                            $result['view'] = array();
                        }
                        $result['view'][] = $permissionDirective['site_id'];
                    }
                }
            }
        }
        $this->logger->debug( print_r($result, true) );
        return $result;
    }


    protected function userExistsRecursive($ldapClient, $userDn, $groupDn)
    {
        $userDnExploded = explode(",", $userDn);
        $userCn = substr($userDnExploded[0], 3); 
        $this->logger->debug("UserAccessGroupMapper::{func}(): Checking to see if {userCn} exists in {groupDn} (recursively)", array(
            'func' => __FUNCTION__,
            'userCn' => $userCn,
            'groupDn' => $groupDn
        ));
        $ldapClient->tmpSearchString = "(&(objectCategory=Person)(cn=". $userCn .")(memberOf:1.2.840.113556.1.4.1941:=". $groupDn ."))";    // Yes. Dodgy as fuck, but cannot use "use"
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

        if ( !is_null($searchResult) && sizeof($searchResult) > 0 ) {
            foreach($searchResult as $sr) {
                if ( strtolower($sr['dn']) === strtolower($userDn) ) {
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
        $result->addPotentialGroupPermission( Config::getEntitlementsSuperuserDN(), 'superuser' );

        // Get Group DNs
        $siteDNs = Config::getGroupEntitlements();
        $entitlements = array();
        foreach($siteDNs as $entitlementDescriptor => $entitlementDn) {
            $entitlementInfo = explode("_", $entitlementDescriptor);
            $entitlements[] = array(
                'site_id' => $entitlementInfo[2],
                'access_level' => $entitlementInfo[3],
                'entitlement_dn' => $entitlementDn
            );
        }

        $result->addPotentialGroupPermissionForAccessLevel($entitlements, 'admin');
        $result->addPotentialGroupPermissionForAccessLevel($entitlements, 'view');

        return $result;
    }

    private function addPotentialGroupPermissionForAccessLevel($allEntitlements, $accessLevel) {
        $entitlements = array_filter($allEntitlements, function ($el) use($accessLevel) {
            return $el['access_level'] === $accessLevel;
        });
        forEach($entitlements as $entitlement) {
            $this->addPotentialGroupPermission($entitlement['entitlement_dn'], $accessLevel, $entitlement['site_id']);
        }
    }

}