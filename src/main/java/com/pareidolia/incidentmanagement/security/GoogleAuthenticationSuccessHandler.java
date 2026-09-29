package com.pareidolia.incidentmanagement.security;

import com.pareidolia.incidentmanagement.service.AppUserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class GoogleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AppUserService appUserService;
    private final String frontendUrl;

    public GoogleAuthenticationSuccessHandler(
            AppUserService appUserService,
            @Value("${app.frontend-url}") String frontendUrl
    ) {
        this.appUserService = appUserService;
        this.frontendUrl = frontendUrl;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        if (!(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        appUserService.provisionUser(oidcUser);
        response.sendRedirect(frontendUrl);
    }
}
