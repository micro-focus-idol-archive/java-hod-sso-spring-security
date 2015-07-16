/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.token.TokenProxy;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@EqualsAndHashCode(callSuper = true)
public class HodAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -4998948982652372121L;

    private final TokenProxy combinedTokenProxy;
    private final String username;
    private final String domain;
    private final String application;

    public HodAuthentication(
            final TokenProxy combinedTokenProxy,
            final Collection<? extends GrantedAuthority> authorities,
            final String username,
            final String domain,
            final String application
    ) {
        super(authorities);
        super.setAuthenticated(true);
        this.domain = domain;
        this.application = application;
        this.username = username;
        this.combinedTokenProxy = combinedTokenProxy;
    }

    @Override
    public AuthenticationToken getCredentials() {
        return null;
    }

    @Override
    public String getPrincipal() {
        return username;
    }

    /**
     * Note: This is not sufficient for access control decisions, the GrantedAuthorities should be checked for the correct
     * {@link HodApplicationGrantedAuthority} instead.
     * @return The HOD application associated with the user
     */
    public String getApplication() {
        return application;
    }

    public String getDomain() {
        return domain;
    }

    public TokenProxy getTokenProxy() {
        return combinedTokenProxy;
    }

    @Override
    public void setAuthenticated(final boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted");
        }

        super.setAuthenticated(false);
    }
}
