/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;

@EqualsAndHashCode
public class HodApplicationGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = 3788810459275972261L;
    public static final String PREFIX = "HOD_";

    private final String authority;

    public HodApplicationGrantedAuthority(final ResourceIdentifier resourceIdentifier) {
        authority = PREFIX + resourceIdentifier.toString();
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
