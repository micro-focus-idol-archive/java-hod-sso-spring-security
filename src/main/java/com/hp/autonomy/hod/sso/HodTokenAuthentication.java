/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class HodTokenAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -643920242131375593L;

    private AuthenticationToken token;

    public HodTokenAuthentication(final AuthenticationToken token) {
        super(null);
        super.setAuthenticated(false);
        this.token = token;
    }

    @Override
    public AuthenticationToken getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public void setAuthenticated(final boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        token = null;
    }
}
