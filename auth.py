#!/usr/bin/env python

import os
import sys
import ldap
import ConfigParser as parser
from passlib.apache import HtpasswdFile

def get_config():

	dir_path = os.path.dirname(os.path.realpath(__file__))
	acl_config = "%s/config.ini" % dir_path

	print "Config file %s" % acl_config

	if os.path.isfile(acl_config) != True:
		print "Config file does not exist."
		exit(1)

	uconfig = parser.ConfigParser()
	uconfig.read(acl_config)

	return uconfig

def check_password(environ, user, password):

	local_user = False
	uconfig = get_config()

	users_str = uconfig.get("local_users","users")
	htpwdfile = uconfig.get("local_users","passwd_file")

	users_lst = users_str.split(',')
	ht = HtpasswdFile(htpwdfile)
	users = []

	for u in users_lst:
		u = u.strip()
		users.append(u)

	if user in users:
		local_user = True
		print "User %s is a local user." % user
		if ht.verify(user,password) is False:
			print "Incorrect credentials."
			return False
			exit(1)

	if local_user is False:
	
		dir_path = os.path.dirname(os.path.realpath(__file__))
		ldap_config_file = "%s/ldap.ini" % dir_path
		lconfig = parser.ConfigParser()
		lconfig.read(ldap_config_file)
		
		ldap_uri = lconfig.get('common','ldap_uri').strip()
		base_dn = lconfig.get('common','base_dn').strip()
		bind_dn = lconfig.get('common','bind_dn').strip()
		bind_pw = lconfig.get('common','bind_pw').strip()

		scope = ldap.SCOPE_SUBTREE
		filter = "(&(objectClass=user)(sAMAccountName=%s))" % user
		attrs = ["sAMAccountName"]
		success = None

		try:	
			
			l = ldap.initialize(ldap_uri)
			l.protocol_version = 3
			l.set_option(ldap.OPT_REFERRALS, 0)
			l.simple_bind_s(bind_dn, bind_pw)
			user_dn = l.search_s(base_dn, scope, filter, attrs)[0][0]
			l.unbind()

		except ldap.INVALID_CREDENTIALS:
			print "Wrong credentials provided for the binding account."
			return False
			exit(1)
		except ldap.LDAPError, e:
			print e
			exit(1)

		try:

			ul = ldap.initialize(ldap_uri)
			ul.protocol_version = 3
			ul.set_option(ldap.OPT_REFERRALS, 0)
			success = ul.simple_bind_s(user_dn, password) or False
			ul.unbind()

		except ldap.INVALID_CREDENTIALS:
			print "Wrong user credentials provided."
			return False
			exit(1)
		except ldap.LDAPEror, e:
			print e
			exit(1)

		if success is False:
			print "Password Failed"
			return False
			exit(1)

		else:
			print "Password Verified"

	uri = environ['REQUEST_URI']

	if uri is None:
		return False

	repo_name = None
	user_perm = None

	if uri.find('\/git\/'):
		repo_name = uri[5:].split("/")[0].strip()
		print "Found repo on uri: %s" % repo_name

	else:
		return False

	if repo_name is None:
		return False

	
	if uconfig.has_section(repo_name):
		print "Checking permission for user %s" % user
		if uconfig.has_option(repo_name, user) == False:
			print "No entry found for user %s." % user
			return False
		else:
			user_perm =  uconfig.get(repo_name, user)
			if uri.find("git-receive-pack") != -1:
				if user_perm.find('w') != -1:
					print "Found write permission for user %s." %user
					return True
				else:
					print "Write permission is needed for this action."
					return False
			else:
				if user_perm.find('r') != -1:
					print "Found read permission for user %s." %user
					return True
				else:
					print "Read permission is needed for this action."
					return False
	else:
		print "Unable to find configuration for %s." % repo_name
		return False

	return True
