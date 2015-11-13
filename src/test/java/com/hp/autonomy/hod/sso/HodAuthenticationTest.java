/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.google.common.collect.ImmutableMap;
import com.hp.autonomy.hod.client.api.authentication.AuthenticationType;
import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.AuthenticationInformation;
import com.hp.autonomy.hod.client.api.authentication.tokeninformation.UserStoreInformation;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.token.TokenProxy;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class HodAuthenticationTest {
    private static final UUID TENANT_UUID = UUID.fromString("852bbbc1-91cd-429b-8e4e-ff29a31678e5");
    private static final UUID USER_UUID = UUID.fromString("847e1504-5c4d-4c59-87e8-87634f3f3b17");
    private static final String NAME = "fred";
    private static final ResourceIdentifier APPLICATION = new ResourceIdentifier("app-domain", "app-name");

    private static final AuthenticationInformation APP_AUTHENTICATION = new AuthenticationInformation(
            UUID.fromString("7b012328-78bf-11e5-8bcf-feff819cdc9f"),
            AuthenticationType.LEGACY_API_KEY
    );

    private static final AuthenticationInformation USER_AUTHENTICATION = new AuthenticationInformation(
            UUID.fromString("8d756f5a-78bf-11e5-8bcf-feff819cdc9f"),
            AuthenticationType.LEGACY_API_KEY
    );

    private static final UserStoreInformation USER_STORE = new UserStoreInformation(
            UUID.fromString("5dcc0ec6-78bf-11e5-8bcf-feff819cdc9f"),
            "store-domain",
            "store-name"
    );

    private static final Map<String, Serializable> METADATA = ImmutableMap.<String, Serializable>builder()
            .put("name", "fred")
            .put("age", 14)
            .build();

    private static final HodAuthenticationPrincipal PRINCIPAL = new HodAuthenticationPrincipal(
            TENANT_UUID,
            USER_UUID,
            APPLICATION,
            USER_STORE,
            APP_AUTHENTICATION,
            USER_AUTHENTICATION,
            NAME,
            METADATA
    );

    private static final GrantedAuthority GRANTED_AUTHORITY = new SimpleGrantedAuthority("ROLE_ADMIN");

    @Test
    public void serializesAndDeserializes() throws IOException, ClassNotFoundException {
        final HodAuthentication authentication = new HodAuthentication(
            new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE),
            Collections.singleton(GRANTED_AUTHORITY),
            PRINCIPAL
        );

        final HodAuthentication outputAuthentication = writeAndReadObject(authentication);
        assertThat(outputAuthentication, is(authentication));
    }

    @Test
    public void deserializes() throws IOException, ClassNotFoundException {
        final HodAuthentication deserializedAuthentication = deserializeFromResource("serializedHodAuthentication.ser");
        assertThat(deserializedAuthentication.getTokenProxy(), not(nullValue()));

        final Collection<GrantedAuthority> authorities = deserializedAuthentication.getAuthorities();
        assertThat(authorities, contains(GRANTED_AUTHORITY));

        final HodAuthenticationPrincipal principal = deserializedAuthentication.getPrincipal();
        assertThat(principal.getTenantUuid(), is(TENANT_UUID));
        assertThat(principal.getUserUuid(), is(USER_UUID));
        assertThat(principal.getApplication(), is(APPLICATION));
        assertThat(principal.getUserStoreInformation(), is(USER_STORE));
        assertThat(principal.getApplicationAuthentication(), is(APP_AUTHENTICATION));
        assertThat(principal.getUserAuthentication(), is(USER_AUTHENTICATION));
        assertThat(principal.getUserMetadata(), is(METADATA));
        assertThat(principal.getName(), is(NAME));
    }

    private <T extends Serializable> T deserializeFromResource(final String resourcePath) throws IOException, ClassNotFoundException {
        try (InputStream inputStream = getClass().getResourceAsStream(resourcePath)) {
            final ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            //noinspection unchecked
            return (T) objectInputStream.readObject();
        }
    }

    private <T extends Serializable> T writeAndReadObject(final T object) throws IOException, ClassNotFoundException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        objectOutputStream.close();

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        final ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);

        //noinspection unchecked
        return (T) objectInputStream.readObject();
    }
}
