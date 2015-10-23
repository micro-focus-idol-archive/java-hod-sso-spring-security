/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import java.io.Serializable;
import java.util.Map;

/**
 * Strategy interface for resolving a username from a map of HOD user metadata.
 */
public interface HodUsernameResolver {

    /**
     * Resolve the username from a map of HOD user metadata
     * @param metadata The user's metadata
     * @return The username or null if there isn't one
     */
    String resolve(Map<String, Serializable> metadata);

}
