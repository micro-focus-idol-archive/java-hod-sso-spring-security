/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.AuthenticationToken;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.token.TokenProxy;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

/**
 * Spring Security Authentication which combines an HP Haven OnDemand {@link TokenProxy} with a username and application
 * details. This Authentication is authenticated at creation time
 * For access control decisions, the GrantedAuthorities should be checked for the correct
 * {@link HodApplicationGrantedAuthority}
 */
@EqualsAndHashCode(callSuper = true)
public class HodAuthentication extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -8505398304901010960L;

    private final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy;
    private final String username;
    private final ResourceIdentifier application;
    private final ResourceIdentifier userStore;
    private final UUID tenantUuid;

    /**
     * Creates a new HodAuthentication
     * @param combinedTokenProxy The TokenProxy associated with the session
     * @param authorities The GrantedAuthorities associated with the session
     * @param username The HP Haven OnDemand username associated with the session
     * @param application The application associated with the session
     * @param userStore The user store associated with the session
     * @param tenantUuid The UUID of the tenant associated with the session
     */
    public HodAuthentication(
        final TokenProxy<EntityType.Combined, TokenType.Simple> combinedTokenProxy,
        final Collection<? extends GrantedAuthority> authorities,
        final String username,
        final ResourceIdentifier application,
        final ResourceIdentifier userStore,
        final UUID tenantUuid
    ) {
        super(authorities);
        super.setAuthenticated(true);

        this.application = application;
        this.userStore = userStore;
        this.tenantUuid = tenantUuid;
        this.username = username;
        this.combinedTokenProxy = combinedTokenProxy;
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
     * @return The HP Haven OnDemand username associated with the session
     */
    @Override
    public String getPrincipal() {
        return username;
    }

    /**
     * @return The HP Haven OnDemand application associated with the session
     */
    public ResourceIdentifier getApplication() {
        return application;
    }

    /**
     * @return The HP Haven OnDemand user store associated with the session
     */
    public ResourceIdentifier getUserStore() {
        return userStore;
    }

    /**
     * @return The UUID of the tenant associated with the session
     */
    public UUID getTenantUuid() {
        return tenantUuid;
    }

    /**
     * @return The {@link TokenProxy} associated with the session
     */
    public TokenProxy<EntityType.Combined, TokenType.Simple> getTokenProxy() {
        return combinedTokenProxy;
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
