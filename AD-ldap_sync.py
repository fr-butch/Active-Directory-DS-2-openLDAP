#!/usr/bin/env python
#-*- coding: utf-8 -*-

''' 
sync users (with passwords hashes) from AD ldap server to OpenLdap with specified base dn (ou=people,ou=ADusers,dc=local,dc=my)

passwords sha1hex store in division attr (AD) using sha1hexfltr on windows server
password updates: for exist users in OpenLdap accounts check that pwdLastSet from AD DS > sambaPwdLastSet in openldap and update both userpw and last change date
'''

import sys, ldap
import ldap.modlist as modlist

from config import *

class LdapCon:
    '''simple ldap class for search\modify\add'''
    def __init__(self,s,u=None,p=None):
        '''u and p - bind user and password'''
        self.u=u
        self.s=s
        self.p=p
        try:
            l=ldap.initialize(self.s)
            if self.u and self.p:
               l.bind_s(self.u,self.p)
        except:
            l=False
            print('Error while connection to ldap server %s with user = %s' % (s,u))
        finally:
            self.l=l

    def __del__(self):
        if self.l:
            self.l.unbind()

    def search(self, bdn, fltr, scope=ldap.SCOPE_SUBTREE):
        ''' attrs=('*',)
        '''
        if self.l:
            result = self.l.search_s(bdn, scope, fltr)
        else:
            result = False
        return(result)
        
    def modify(self, dn, ldif):
        ''' use ldap Modlist '''
        res=False
        if self.l:
            try:
                res=self.l.modify_s(dn, ldif)
                #print('Modify record  %s with Modlist:\n' % dn)
                #print(ldif)
            except:
                print('Error while modify record  %s with Modlist:\n' % dn )
                print(ldif)
        return(res)
    
    def add(self, dn, ldif):
        ''' use ldap Modlist '''
        res=False
        if self.l:
            try:
                res=self.l.add_s(dn, ldif)
                #print('Adding record  %s with Modlist:\n' % dn)
                #print(ldif)
            except:
                print('Error while add record  %s with Modlist:\n' % dn )
                print(ldif)
        return(res)

   

def getlastuid(b_dn='dc=domain,dc=loc', u_fltr='(&(objectClass=posixAccount)(uidNumber=*))'):
    ''' get all uidNumber's for posixAccs in OpenLDAP, order them and get last
    '''
    ldap_uids = LdapCon(server_l).search(b_dn, u_fltr)
    if ldap_uids:
        uids = sorted( [int(x[1]['uidNumber'][0]) for x in ldap_uids] )
        last = uids[-1]
    else:
        print('cant get last uidNumber - ldap problem?')
        last=False
    return(last)


def sha1hex2ldap(sha1hex):   
    ''' get sha1hex from AD DS - division attr,
        decode\encode for openldap userpassword attr.
        rstrip removes newline after encode('base64')
    '''
    ldaphash='{SHA}' + sha1hex.decode('hex').encode('base64').rstrip()
    # if needed
    #.encode('base64').rstrip() 
    return(ldaphash)

def ft2ut(ft):
    ''' convert microsoft filetime to unixtime
    '''
    ut=(long(ft) - 116444736000000000) / 10000000
    return(ut)
    
    
    
ADusers = LdapCon(server,user_dn,user_pw).search(base_dn, user_fltr)
LDAPusers = LdapCon(server_l).search(base_dn_l, user_fltr_l)
   
if not (ADusers or LDAPusers):
    sys.exit(2)

#get here {uid: lastpwreset, } 
ldap_accs =  dict([ (x[1]['uid'][0], x[1]['sambaPwdLastSet'][0]) for x in LDAPusers])

for auser in ADusers:
    au=auser[1]
    au_uid=au['sAMAccountName'][0]
    #if excluded account or have no division (sha1hex) attr - skip
    if (au_uid in exclude_dn) or (au.get('division', None) == None):
       #print('%s in exclude_dn or has no division attr' % au_uid)
       continue
    # look for user acounts in AD
    # for each sAMAccountName check if uid exist in ou=some-ou, if not - create in openldap
    # if password was updated - update in openldap
    if au_uid in ldap_accs:
        #check if we need password update
        pwdLS = ft2ut( au['pwdLastSet'][0] )
        ldap_acc = dict(LDAPusers)[dn_prod % au_uid]
        if pwdLS > int( ldap_acc['sambaPwdLastSet'][0] ) + 1:
            # modify - sambaPwdLastSet, userPassword
            old = {'userPassword': ldap_acc['userPassword'],
                   'sambaPwdLastSet': ldap_acc['sambaPwdLastSet'] }
            upwd = sha1hex2ldap( au['division'][0] )
            new = {'userPassword': [upwd],
                   'sambaPwdLastSet': [str(pwdLS)]}
            # Convert place-holders for modify-operation using modlist-module
            ldif = modlist.modifyModlist(old,new)
            if not LdapCon(server_l,user_dn_l,user_pw_l).modify(dn_prod % au_uid,ldif):
                print('cant modify record  %s with Modlist:\n' % au_uid)
                print(ldif) 
    else:
        # create user, if not exist such dn
        attrs = user_tpl
        try:
            for attr in ('cn','givenName','sn','telephoneNumber','mail'):
                attrs[attr] = au[attr]
            attrs['homeDirectory'] = ['/home/%s' % au_uid]
            attrs['homePhone'] = au['telephoneNumber']
        except KeyError:
            print('Error: some of required attrs missed in AD account %s' % au_uid)
            continue
        attrs['sambaPwdLastSet'] = [str( ft2ut(au['pwdLastSet'][0]) )]
        attrs['uid'] = [au_uid]
        attrs['userPassword'] = [ sha1hex2ldap(au['division'][0]) ]
        uidn = getlastuid()
        if uidn:
            attrs['uidNumber'] = [ str( uidn+1 ) ]
            # Convert our dict to nice syntax for the add-function using modlist-module
            ldif = modlist.addModlist(attrs)
            if LdapCon(server_l,user_dn_l,user_pw_l).add(dn_prod % au_uid, ldif):
               print('Added record %s with addModlist:\n'  % au_uid)
               print(ldif)
            else:
               print('Cant add record %s with addModlist:\n' % au_uid)
               print(ldif)
        else:
            print('Cant get uniq uidNumber for new ldap account %s' % au_uid)
            continue

