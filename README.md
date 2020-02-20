# gremlin-ldap-plugin
LDAP authentication plugin for gremlin server

To use the plugin:
- Copy the jar file to gremlin server lib folder.
- Configure com.github.vjgorla.gremlin.security.LdapAuthenticator as the authenticator in server configuration yaml file. (example below). 

```
channelizer: org.apache.tinkerpop.gremlin.server.channel.HttpChannelizer
authentication: {
   authenticator: com.github.vjgorla.gremlin.security.LdapAuthenticator,
   authenticationHandler: org.apache.tinkerpop.gremlin.server.handler.HttpBasicAuthenticationHandler,
   config: {
     ldapCtxFactory: com.sun.jndi.ldap.LdapCtxFactory,
     ldapProviderUrl: "ldap://myldaphost:636",
     ldapSecurityProtocol: ssl,
     ldapSecurityAuth: simple,
     ldapBindAccountDn: "cn=myserverbindaccount,ou=users,dc=xyz,dc=com",
     ldapBindAccountPassword: "myserverbindpwd",
     ldapUserRootDn: "ou=users,dc=xyz,dc=com",
     # User must belong to the group below to succussfully authenticate
     ldapAuthorisedGroupDn: "cn=my_gremlin_users,ou=groups,dc=xyz,dc=com"
   }
}

```
