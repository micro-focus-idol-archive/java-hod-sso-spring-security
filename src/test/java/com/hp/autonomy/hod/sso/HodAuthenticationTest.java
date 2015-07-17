/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import com.hp.autonomy.hod.client.token.TokenProxy;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Collection;
import java.util.Collections;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class HodAuthenticationTest {
    @Test
    public void serializesWhenAuthenticated() throws IOException, ClassNotFoundException {
        final String username = "my-username";
        final String applicationName = "my-application";
        final String domain = "my-domain";
        final TokenProxy combinedTokenProxy = new TokenProxy();

        final Collection<GrantedAuthority> authorities = Collections.emptySet();
        final HodAuthentication authentication = new HodAuthentication(combinedTokenProxy, authorities, username, domain, applicationName);

        final HodAuthentication outputAuthentication = writeAndReadAuthentication(authentication);

        assertThat(outputAuthentication.getPrincipal(), is(username));
        assertThat(outputAuthentication.getApplication(), is(applicationName));
        assertThat(outputAuthentication.getDomain(), is(domain));
        assertThat(outputAuthentication.getTokenProxy(), is(combinedTokenProxy));
        assertThat(outputAuthentication.isAuthenticated(), is(true));
        assertThat(outputAuthentication.getCredentials(), is(nullValue()));
    }

    private HodAuthentication writeAndReadAuthentication(final HodAuthentication authentication) throws IOException, ClassNotFoundException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(authentication);
        objectOutputStream.close();

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        final ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        return (HodAuthentication) objectInputStream.readObject();
    }
}
