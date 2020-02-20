package com.github.vjgorla.gremlin.security;

import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.PROPERTY_PASSWORD;
import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.PROPERTY_USERNAME;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticationException;
import org.apache.tinkerpop.gremlin.server.auth.Authenticator;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 *
 * @author Vijaya Gorla
 */
public class LdapAuthenticator implements Authenticator {
    
    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticator.class);
    private static final byte NUL = 0;
    
    interface ConfigKeys {
        String LDAP_INITIAL_CONTEXT_FACTORY = "ldapCtxFactory";
        String LDAP_PROVIDER_URL = "ldapProviderUrl";
        String LDAP_SECURITY_PROTOCOL = "ldapSecurityProtocol";
        String LDAP_SECURITY_AUTHENTICATION = "ldapSecurityAuth";
        String LDAP_BIND_ACCOUNT_DN = "ldapBindAccountDn";
        String LDAP_BIND_ACCOUNT_PASSWORD = "ldapBindAccountPassword";
        String LDAP_USER_ROOT_DN = "ldapUserRootDn";
        String LDAP_AUTHORISED_GROUP_DN = "ldapAuthorisedGroupDn";
        String CREDENTIAL_CACHE_TTL_MINS = "credentialCacheTtlMins";
    }

    private Cache<String, String> cache;
    private int credentialCacheTtlMins;
    private Hashtable<String, String> ldapEnv;
    private String ldapBindAccountDn;
    private String ldapBindAccountPassword;
    private String ldapUserRootDn;
    private String ldapAuthorisedGroupDn;

    @Override
    public boolean requireAuthentication() {
        return true;
    }

    @Override
    public void setup(final Map<String,Object> config) {
        logger.info("Initializing authentication with {}", LdapAuthenticator.class.getName());

        if (config == null) {
            throw new IllegalArgumentException(String.format(
                    "Could not configure a %s - provide a 'config' in the 'authentication' settings",
                    LdapAuthenticator.class.getName()));
        }
        
        this.ldapEnv = new Hashtable<>();
        this.ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, getConfigValue(config, ConfigKeys.LDAP_INITIAL_CONTEXT_FACTORY));
        this.ldapEnv.put(Context.PROVIDER_URL, getConfigValue(config, ConfigKeys.LDAP_PROVIDER_URL));
        this.ldapEnv.put(Context.SECURITY_PROTOCOL, getConfigValue(config, ConfigKeys.LDAP_SECURITY_PROTOCOL));
        this.ldapEnv.put(Context.SECURITY_AUTHENTICATION, getConfigValue(config, ConfigKeys.LDAP_SECURITY_AUTHENTICATION));
        
        this.ldapBindAccountDn = getConfigValue(config, ConfigKeys.LDAP_BIND_ACCOUNT_DN);   
        this.ldapBindAccountPassword = getConfigValue(config, ConfigKeys.LDAP_BIND_ACCOUNT_PASSWORD);

        this.ldapUserRootDn = getConfigValue(config, ConfigKeys.LDAP_USER_ROOT_DN); 
        this.ldapAuthorisedGroupDn = getConfigValue(config, ConfigKeys.LDAP_AUTHORISED_GROUP_DN);   
        
        this.credentialCacheTtlMins = getConfigValue(config, ConfigKeys.CREDENTIAL_CACHE_TTL_MINS);
        this.cache = CacheBuilder.newBuilder()
			       .maximumSize(5000)
			       .expireAfterWrite(this.credentialCacheTtlMins, TimeUnit.MINUTES)
			       .build();
    }

    @Override
    public SaslNegotiator newSaslNegotiator(final InetAddress remoteAddress) {
        return new PlainTextSaslAuthenticator();
    }

    @Override
    public AuthenticatedUser authenticate(final Map<String, String> credentials) throws AuthenticationException {
        if (!credentials.containsKey(PROPERTY_USERNAME)) throw new IllegalArgumentException(String.format("Credentials must contain a %s", PROPERTY_USERNAME));
        if (!credentials.containsKey(PROPERTY_PASSWORD)) throw new IllegalArgumentException(String.format("Credentials must contain a %s", PROPERTY_PASSWORD));

        final String username = credentials.get(PROPERTY_USERNAME);
        final String password = credentials.get(PROPERTY_PASSWORD);
        
        String cachedPwdHash = this.cache.getIfPresent(username);
        if (cachedPwdHash != null) {
        	if (!BCrypt.checkpw(password, cachedPwdHash)) {
        		throw new AuthenticationException("Username and/or password are incorrect");
        	}
        } else {
        	this.ldapAuthenticate(username, password);
        	// Successful. Store hashed password in cache to improve performance
        	String pwdHash = BCrypt.hashpw(password, BCrypt.gensalt(4));
        	this.cache.put(username, pwdHash);
        }

        return new AuthenticatedUser(username);
    }
    
    private void ldapAuthenticate(String username, String password) throws AuthenticationException {
        String userDn = "uid=" + username + "," + this.ldapUserRootDn;
        logger.debug("Authenticating user {} using LDAP", username);
        
        // For authentication, use the username+password provided by the client to connect to LDAP
        LdapContext ctx = null;
        try {
            ctx = this.createContext(userDn, password);
        } catch (Exception ex) {
            logger.debug("Authentication failed for user {} with error {}", userDn, ex.getLocalizedMessage());
            throw new AuthenticationException("Username and/or password are incorrect");
        } finally {
            closeLdapContext(ctx);
        }
        logger.debug("Authentication successful for user {}", userDn);
        
        boolean isAuthorised = this.isAuthorised(userDn);
        if (!isAuthorised) {
            logger.debug("User {} does not belong to authorised group {}", userDn, this.ldapAuthorisedGroupDn);
            throw new AuthenticationException("User does not belong to authorised group");
        }    	
    }
    
    private boolean isAuthorised(String userDn) throws AuthenticationException {
        logger.debug("Checking if user {} belongs to authorised group {}", userDn, this.ldapAuthorisedGroupDn);
         // Where as for authorization, use the bind account to connect to LDAP
        LdapContext ctx = null;
        try {
            ctx = this.createContext(this.ldapBindAccountDn, this.ldapBindAccountPassword);
            ctx.setRequestControls(null);
            NamingEnumeration<SearchResult> namingEnum 
                = ctx.search(this.ldapAuthorisedGroupDn, "(&(member=" + userDn + ")(objectClass=groupOfNames))", newLdapSearchControls("cn"));
            boolean isAuthorised = namingEnum.hasMore();
            namingEnum.close();
            return isAuthorised;
        } catch (Exception ex) {
            logger.error("Error looking up roles in LDAP", ex);
            throw new AuthenticationException("Error looking up roles in LDAP", ex);
        } finally {
            closeLdapContext(ctx);
        }
    }
    
    private LdapContext createContext(String userDn, String password) throws NamingException {
        Hashtable<String, String> authLdapEnv = new Hashtable<>(this.ldapEnv);
        authLdapEnv.put(Context.SECURITY_PRINCIPAL, userDn);
        authLdapEnv.put(Context.SECURITY_CREDENTIALS, password);
        return new InitialLdapContext(authLdapEnv, null);
    }
    
    @SuppressWarnings("unchecked")
	private static <T> T getConfigValue(final Map<String,Object> config, String key) {
        T value = (T)config.get(key);
        if (value == null) {
            throw new IllegalStateException(String.format("Authentication configuration missing the %s key", key));
        }
        return value;
    }

    private static SearchControls newLdapSearchControls(String... attrs) {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setTimeLimit(30000);
        searchControls.setReturningAttributes(attrs);
        return searchControls;
    }
    
    private static void closeLdapContext(LdapContext ctx) {
        if (ctx != null) {
            try { 
                ctx.close();
            } catch (Exception ex) {
                logger.warn("Error closing LDAP context", ex);
            }
        }   
    }

    private class PlainTextSaslAuthenticator implements Authenticator.SaslNegotiator {
        private boolean complete = false;
        private String username;
        private String password;

        @Override
        public byte[] evaluateResponse(final byte[] clientResponse) throws AuthenticationException {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        @Override
        public boolean isComplete() {
            return complete;
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (!complete) throw new AuthenticationException("SASL negotiation not complete");
            final Map<String,String> credentials = new HashMap<>();
            credentials.put(PROPERTY_USERNAME, username);
            credentials.put(PROPERTY_PASSWORD, password);
            return authenticate(credentials);
        }

        /**
         * SASL PLAIN mechanism specifies that credentials are encoded in a
         * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
         * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}.
         *
         * @param bytes encoded credentials string sent by the client
         */
        private void decodeCredentials(byte[] bytes) throws AuthenticationException {
            byte[] user = null;
            byte[] pass = null;
            int end = bytes.length;
            for (int i = bytes.length - 1 ; i >= 0; i--) {
                if (bytes[i] == NUL) {
                    if (pass == null)
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    else if (user == null)
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    end = i;
                }
            }

            if (null == user) throw new AuthenticationException("Authentication ID must not be null");
            if (null == pass) throw new AuthenticationException("Password must not be null");

            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
        }
    }
}
