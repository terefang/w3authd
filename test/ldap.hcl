ldap_uri = ["ldap://ldap.forumsys.com:389"]
# ldap_start_tls = true
ldap_bind_username = "cn=read-only-admin,dc=example,dc=com"
ldap_bind_password = "password"
ldap_base_dn = "dc=example,dc=com"
# ldap_user_template = "uid={u},dc=example,dc=com"
# ldap_user_base_dn =
ldap_user_search = "(uid={u})"
ldap_user_role_attribute = [ "uid", "mail" ]
# ldap_user_role_attribute_type =
ldap_group_base_dn = "dc=example,dc=com"
ldap_group_search = "(&(uniqueMember={dn})(objectClass=groupOfUniqueNames))"
ldap_group_role_attribute = [ "dn","cn","ou","o" ]
# ldap_group_role_attribute_type =
ldap_allow_roles = [ "scientists" ]