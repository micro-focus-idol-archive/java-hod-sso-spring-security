/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.token.TokenProxy;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Spring Security Authentication which combines an Micro Focus Haven OnDemand {@link TokenProxy} with a username and application
 * details. This Authentication is authenticated at creation time.
 * For access control decisions, the GrantedAuthorities should be checked for the correct
 * {@link HodApplicationGrantedAuthority}.
 * @param <E> Entity type of token proxies contained in the authentication.
 */
@EqualsAndHashCode(callSuper = true)
public class HodAuthentication<E extends EntityType> extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -4211186433120477158L;

    private final TokenProxy<E, TokenType.Simple> tokenProxy;
    private final HodAuthenticationPrincipal principal;

    /**
     * Creates a new HodAuthentication representing a combined token.
     * @param tokenProxy  The TokenProxy associated with the session
     * @param authorities The GrantedAuthorities associated with the session
     * @param principal   The HOD application and user authenticated by this token
     */
    public HodAuthentication(
            final TokenProxy<E, TokenType.Simple> tokenProxy,
            final Collection<? extends GrantedAuthority> authorities,
            final HodAuthenticationPrincipal principal
    ) {
        super(authorities);
        super.setAuthenticated(true);

        this.principal = principal;
        this.tokenProxy = tokenProxy;
    }

    /**
     * This token cannot be re-authenticated, so this method returns null
     * @return null
     */
    @Override
    public AuthenticationToken<?, ?> getCredentials() {
        return null;
    }

    /**
     * @return The Micro Focus Haven OnDemand entities authenticated by this token
     */
    @Override
    public HodAuthenticationPrincipal getPrincipal() {
        return principal;
    }

    /**
     * @return The {@link TokenProxy} associated with the session
     */
    public TokenProxy<E, TokenType.Simple> getTokenProxy() {
        return tokenProxy;
    }

    /**
     * Sets the trusted state of the token. This can only be set to false
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
}
