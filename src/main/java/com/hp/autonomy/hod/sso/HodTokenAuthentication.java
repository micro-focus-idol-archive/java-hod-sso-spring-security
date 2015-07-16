/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * An Authentication representing an unverified HP Haven OnDemand combined token.
 *
 * This authentication is never authenticated.
 */
public class HodTokenAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -643920242131375593L;

    private AuthenticationToken token;

    public HodTokenAuthentication(final AuthenticationToken token) {
        super(null);
        super.setAuthenticated(false);
        this.token = token;
    }

    /**
     * @return The HP Haven OnDemand combined token
     */
    @Override
    public AuthenticationToken getCredentials() {
        return token;
    }

    /**
     * This method returns null as the username has not been obtained yet
     * @return null
     */
    @Override
    public Object getPrincipal() {
        return null;
    }

    /**
     * Sets the trusted state of the authentication. This can only be set to false. Since the authentication's initial
     * state is false, there is no need to call this method
     * @param isAuthenticated True if the token should be trusted; false otherwise
     * @throw IllegalArgumentException If isAuthenticated is set to true
     */
    @Override
    public void setAuthenticated(final boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted");
        }

        super.setAuthenticated(false);
    }

    /**
     * Removes the HP Haven OnDemand combined token from the authentication
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        token = null;
    }
}
