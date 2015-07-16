/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;

/**
 * Represents the authority to use a HP Haven OnDemand application
 */
@EqualsAndHashCode
public class HodApplicationGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = 3788810459275972261L;
    public static final String PREFIX = "HOD_";

    private final String authority;

    /**
     * Creates a new HodApplicationGrantedAuthority with the given ResourceIdentifier
     * @param resourceIdentifier A {@link ResourceIdentifier} representing the application
     */
    public HodApplicationGrantedAuthority(final ResourceIdentifier resourceIdentifier) {
        authority = PREFIX + resourceIdentifier.toString();
    }

    /**
     * @return A String representation of the GrantedAuthority
     */
    @Override
    public String getAuthority() {
        return authority;
    }
}
