package com.pareidolia.incidentmanagement.notification;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** A deployment-controlled HTTPS origin. No request headers or incident metadata enter this URL. */
final class IncidentEmailPortalLink {
    private IncidentEmailPortalLink() { }

    static String url(String configuredOrigin) {
        if (configuredOrigin == null || configuredOrigin.isBlank()) {
            return null; // Preserve existing V2 rendering when no link is configured.
        }
        try {
            URI origin = new URI(configuredOrigin);
            String path = origin.getRawPath();
            if (!"https".equalsIgnoreCase(origin.getScheme()) || origin.getHost() == null
                    || origin.getRawUserInfo() != null || origin.getRawQuery() != null
                    || origin.getRawFragment() != null
                    || (path != null && !path.isEmpty() && !path.equals("/"))
                    || origin.getPort() == 0 || origin.getPort() > 65535) {
                throw new IllegalArgumentException();
            }
            return new URI("https", null, origin.getHost().toLowerCase(Locale.ROOT),
                    origin.getPort(), "/", null, null).toASCIIString();
        } catch (URISyntaxException | IllegalArgumentException invalid) {
            // Never echo potentially sensitive configuration in the startup error.
            throw new IllegalArgumentException("Incident email portal origin must be a plain HTTPS origin.");
        }
    }
}
