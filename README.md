AD-DS-2-openLDAP
================

export users with passwords hash from Active Directory (AD DS) to openLDAP using sha1hexfltr http://code.google.com/p/sha1hexfltr/
updates passwords hash for existing users.
must be run with cron.
requiere python 2.5-2.7 (python-ldap)

Alternative: proxy requests for specifyed suffix from openldap to active directory using ldap backend - slapd-ldap. example slapd conf.:
database        ldap
suffix          "cn=users,dc=testcorp,dc=com"
subordinate
rebind-as-user
uri             "ldap://dc1.testcorp.com/"
chase-referrals yes
