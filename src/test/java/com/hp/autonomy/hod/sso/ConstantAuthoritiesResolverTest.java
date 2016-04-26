/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.token.TokenProxy;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class ConstantAuthoritiesResolverTest {
    @Test
    public void returnsAuthoritiesWithTheGivenRole() {
        final String role = "ROLE_USER";
        final GrantedAuthoritiesResolver resolver = new ConstantAuthoritiesResolver(role);

        final TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy = new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE);
        final Collection<GrantedAuthority> authorities = resolver.resolveAuthorities(tokenProxy, mock(CombinedTokenInformation.class));

        assertThat(authorities, hasSize(1));

        final GrantedAuthority authority = authorities.iterator().next();
        assertThat(authority.getAuthority(), is(role));
    }
}