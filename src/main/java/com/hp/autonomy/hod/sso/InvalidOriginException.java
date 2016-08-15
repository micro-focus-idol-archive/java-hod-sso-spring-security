package com.hp.autonomy.hod.sso;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.net.URL;

/**
 * Indicates that the URL provided did not match the allowed origins.
 */
@Getter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class InvalidOriginException extends Exception {
    private static final long serialVersionUID = -7019284356750980660L;

    private final URL url;

    public InvalidOriginException(final URL url) {
        super("Origin " + url.toString() + " is not allowed");
        this.url = url;
    }
}
