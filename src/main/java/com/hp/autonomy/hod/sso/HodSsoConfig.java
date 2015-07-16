/*
 * Copyright 2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.hod.sso;

import java.util.Set;

public interface HodSsoConfig {

    String getApiKey();

    Set<String> getAllowedOrigins();

}
