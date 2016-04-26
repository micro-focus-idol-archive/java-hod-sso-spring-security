/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.token.TokenProxy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.LinkedList;

/**
 * A GrantedAuthoritiesResolver which gives every authenticated entity the same SimpleGrantedAuthorities.
 */
public class ConstantAuthoritiesResolver implements GrantedAuthoritiesResolver {
    private final String[] authorities;

    /**
     * Construct a new ConstantAuthoritiesResolver with the given string authorities. Typically, these will be prefixed
     * with ROLE_ for use with Spring Security.
     * @param authorities Authorities to give to every user
     */
    public ConstantAuthoritiesResolver(final String... authorities) {
        this.authorities = authorities;
    }

    @Override
    public Collection<GrantedAuthority> resolveAuthorities(
            final TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy,
            final CombinedTokenInformation combinedTokenInformation
    ) {
        final Collection<GrantedAuthority> output = new LinkedList<>();

        for (final String authority : authorities) {
            output.add(new SimpleGrantedAuthority(authority));
        }

        return output;
    }
}
