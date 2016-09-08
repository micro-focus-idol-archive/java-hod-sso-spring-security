package com.hp.autonomy.hod.sso;

import lombok.Data;

import java.io.Serializable;
import java.util.Map;

@SuppressWarnings("WeakerAccess")
@Data
public class HodUserMetadata {
    private final String userDisplayName;
    private final Map<String, Serializable> metadata;
}
