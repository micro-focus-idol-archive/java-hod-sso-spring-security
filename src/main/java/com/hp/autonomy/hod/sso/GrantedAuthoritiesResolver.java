/*
 * Copyright 2015-2018 Micro Focus International plc.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.token.TokenProxy;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Resolves a collection of Spring Security {@link GrantedAuthority} for a HOD combined token.
 */
public interface GrantedAuthoritiesResolver {

    /**
     * Use the provided token proxy and combined token information to resolve application GrantedAuthorities for the
     * entity they represent
     * @param tokenProxy The token proxy used for authentication
     * @param combinedTokenInformation Information about the combined token
     * @return The application GrantedAuthorities
     */
    Collection<GrantedAuthority> resolveAuthorities(TokenProxy<EntityType.Combined, TokenType.Simple> tokenProxy, CombinedTokenInformation combinedTokenInformation);

}
