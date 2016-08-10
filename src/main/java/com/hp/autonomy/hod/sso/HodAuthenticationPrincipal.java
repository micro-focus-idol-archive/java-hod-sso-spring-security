/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.tokeninformation.AuthenticationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.CombinedTokenInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserStoreInformation;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ToStringBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Getter
@EqualsAndHashCode
public class HodAuthenticationPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 8740573190952973889L;

    private final UUID tenantUuid;
    private final UUID userUuid;
    private final ResourceIdentifier application;
    private final UserStoreInformation userStoreInformation;
    private final AuthenticationInformation applicationAuthentication;
    private final AuthenticationInformation userAuthentication;
    private final String name;
    private final String securityInfo;
    private transient Map<String, Serializable> userMetadata;

    public HodAuthenticationPrincipal(
            final UUID tenantUuid,
            final UUID userUuid,
            final ResourceIdentifier application,
            final UserStoreInformation userStoreInformation,
            final AuthenticationInformation applicationAuthentication,
            final AuthenticationInformation userAuthentication,
            final String name,
            final Map<String, Serializable> userMetadata,
            final String securityInfo
    ) {
        this.tenantUuid = tenantUuid;
        this.userUuid = userUuid;
        this.application = application;
        this.userStoreInformation = userStoreInformation;
        this.applicationAuthentication = applicationAuthentication;
        this.userAuthentication = userAuthentication;
        this.name = StringUtils.defaultString(name);
        this.securityInfo = securityInfo;

        this.userMetadata = userMetadata == null ? new HashMap<String, Serializable>() : userMetadata;
    }

    public HodAuthenticationPrincipal(final CombinedTokenInformation tokenInformation, final String name, final Map<String, Serializable> userMetadata) {
        this(
                tokenInformation.getTenantUuid(),
                tokenInformation.getUser().getUuid(),
                tokenInformation.getApplication().getIdentifier(),
                tokenInformation.getUserStore(),
                tokenInformation.getApplication().getAuthentication(),
                tokenInformation.getUser().getAuthentication(),
                name,
                userMetadata,
                null
        );
    }

    public HodAuthenticationPrincipal(final CombinedTokenInformation tokenInformation, final String name, final Map<String, Serializable> userMetadata, final String securityInfo) {
        this(
                tokenInformation.getTenantUuid(),
                tokenInformation.getUser().getUuid(),
                tokenInformation.getApplication().getIdentifier(),
                tokenInformation.getUserStore(),
                tokenInformation.getApplication().getAuthentication(),
                tokenInformation.getUser().getAuthentication(),
                name,
                userMetadata,
                securityInfo
        );
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("tenantUuid", tenantUuid)
                .append("userStore", userStoreInformation.getIdentifier())
                .append("userUuid", userUuid)
                .toString();
    }

    private void writeObject(final ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();

        out.writeInt(userMetadata.size());

        for (final Map.Entry<String, Serializable> entry : userMetadata.entrySet()) {
            out.writeObject(entry.getKey());
            out.writeObject(entry.getValue());
        }
    }

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        userMetadata = new HashMap<>();

        final int size = in.readInt();

        for (int i = 0; i < size; i++) {
            final String key = (String) in.readObject();
            final Serializable value = (Serializable) in.readObject();
            userMetadata.put(key, value);
        }
    }
}
