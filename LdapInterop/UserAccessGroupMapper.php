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
     * An array with each element being a sub array with group_dn, site_id (optional) and access_type (superuser, admin or view)
     * @var array
     */
    private $groupsPermission;

    private function addPotentialGroupPermission($group_dn, $access_type, $site_id = null)
    {
        $tmpGrp = array(
            'group_dn' => $group_dn,
            'access_type' => $access_type,
        );
        if (!is_null($site_id) && is_numeric($site_id)) {
            $tmpGrp['site_id'] = $site_id;
        }
        $this->groupsPermission[] = $tmpGrp;
        $this->logger->debug("UserAccessGroupMapper::{func}(): Users in {group_dn} will be {access_type} for {site}", array(
            'func' => __FUNCTION__,
            'group_dn' => $group_dn,
            'access_type' => $access_type . "s",
            'site' => is_null($site_id) ? "All sites" : "Site ID $site_id"
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
        $this->logger->debug("UserAccessGroupMapper::{func}(): Preparing to look through all potential groups.", array(
            'func' => __FUNCTION__
        ));

        // Get the Ldap Connection in case we need to search
        $ldapClient = LdapUsers::makeConfigured();

        // Direct memberships are easier to resolve against (ie. 'memberOf' in AD)
        $memberOfAttribute = Config::getRequiredMemberOfField();
        $direct_memberships = array();
        if (array_key_exists(strtolower($memberOfAttribute), $ldapUser)) {
            $direct_memberships = array_map(function($tmp_dn) {
                return strtolower($tmp_dn);
            }, $ldapUser[strtolower($memberOfAttribute)]);
        }

        $this->logger->debug("UserAccessGroupMapper::{func}(): Direct Memberships: {memberships}", array(
            'func' => __FUNCTION__,
            'memberships' => print_r($direct_memberships, true)
        ));

        // Loop through all the group checks
        foreach( $this->groupsPermission as $permission_directive ) {
            // Check Direct membership first
            $tmp_group_member = false;

            if ( in_array( strtolower($permission_directive['group_dn']), $direct_memberships ) ) {
                $tmp_group_member = true;
            }
            

            if ($tmp_group_member === false) {
                // If it's AD, we can do a recursive search
                $tmp_group_member = $this->userExistsRecursive($ldapClient, $ldapUser['dn'], $permission_directive['group_dn']);
            }

            if ($tmp_group_member === true) {
                // Superuser
                if ($permission_directive['access_type'] === 'superuser') {
                    return array('superuser' => true);
                }
            }

        }

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
        return $result;
    }

}