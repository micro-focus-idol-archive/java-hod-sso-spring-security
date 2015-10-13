/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.api.authentication.EntityType;
import com.hp.autonomy.hod.client.api.authentication.TokenType;
import com.hp.autonomy.hod.client.api.resource.ResourceIdentifier;
import com.hp.autonomy.hod.client.token.TokenProxy;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Collections;
import java.util.UUID;

import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class HodAuthenticationTest {
    private static final String USERNAME = "my-username";
    private static final ResourceIdentifier APPLICATION = new ResourceIdentifier("app-domain", "app-name");
    private static final UUID TENANT_UUID = UUID.fromString("852bbbc1-91cd-429b-8e4e-ff29a31678e5");
    private static final ResourceIdentifier USER_STORE = new ResourceIdentifier("store-domain", "store-name");

    @Test
    public void serializesAndDeserializes() throws IOException, ClassNotFoundException {
        final HodAuthentication authentication = new HodAuthentication(
            new TokenProxy<>(EntityType.Combined.INSTANCE, TokenType.Simple.INSTANCE),
            Collections.<GrantedAuthority>emptySet(),
            USERNAME,
            APPLICATION,
            USER_STORE,
            TENANT_UUID
        );

        final HodAuthentication outputAuthentication = writeAndReadObject(authentication);
        assertThat(outputAuthentication, is(authentication));
    }

    @Test
    public void deserializes() throws IOException, ClassNotFoundException {
        final HodAuthentication deserializedAuthentication = deserializeFromResource("serializedHodAuthentication.ser");
        assertThat(deserializedAuthentication.getPrincipal(), is(USERNAME));
        assertThat(deserializedAuthentication.getApplication(), is(APPLICATION));
        assertThat(deserializedAuthentication.getUserStore(), is(USER_STORE));
        assertThat(deserializedAuthentication.getTenantUuid(), is(TENANT_UUID));

        assertThat(deserializedAuthentication.getAuthorities(), is(empty()));

        assertThat(deserializedAuthentication.getTokenProxy(), not(nullValue()));
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
