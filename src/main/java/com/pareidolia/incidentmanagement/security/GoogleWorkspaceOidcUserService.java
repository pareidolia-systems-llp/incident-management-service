package com.pareidolia.incidentmanagement.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class GoogleWorkspaceOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OidcUserService delegate = new OidcUserService();
    private final String allowedDomain;

    public GoogleWorkspaceOidcUserService(@Value("${app.auth.allowed-domain}") String allowedDomain) {
        this.allowedDomain = allowedDomain.trim().toLowerCase(Locale.ROOT);
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = delegate.loadUser(userRequest);
        String hostedDomain = oidcUser.getClaimAsString("hd");
        Boolean emailVerified = oidcUser.getClaimAsBoolean("email_verified");

        if (!allowedDomain.equals(normalizeDomain(hostedDomain)) || !Boolean.TRUE.equals(emailVerified)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_workspace_account"),
                    "Google account is not authorized for this application."
            );
        }
        return oidcUser;
    }

    private String normalizeDomain(String domain) {
        return domain == null ? "" : domain.trim().toLowerCase(Locale.ROOT);
    }
}
