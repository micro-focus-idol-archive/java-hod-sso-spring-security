/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * An Authentication representing an unverified HP Haven OnDemand combined SSO token.
 * <p>
 * This authentication is never authenticated.
 */
public class HodTokenAuthentication<E extends EntityType> extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -643920242131375593L;

    private AuthenticationToken<E, TokenType.Simple> token;

    public HodTokenAuthentication(final AuthenticationToken<E, TokenType.Simple> token) {
        super(null);
        super.setAuthenticated(false);
        this.token = token;
    }

    /**
     * @return The HP Haven OnDemand combined token
     */
    @Override
    public AuthenticationToken<E, TokenType.Simple> getCredentials() {
        return token;
    }

    /**
     * This method returns null as the user details have not been obtained yet
     *
     * @return null
     */
    @Override
    public Object getPrincipal() {
        return null;
    }

    /**
     * Sets the trusted state of the authentication. This can only be set to false. Since the authentication's initial
     * state is false, there is no need to call this method
     *
     * @param isAuthenticated True if the token should be trusted; false otherwise
     * @throws IllegalArgumentException If isAuthenticated is set to true
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
