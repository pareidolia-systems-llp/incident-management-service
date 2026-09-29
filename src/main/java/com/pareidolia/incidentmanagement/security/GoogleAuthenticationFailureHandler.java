package com.pareidolia.incidentmanagement.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class GoogleAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final String failureRedirectUrl;

    public GoogleAuthenticationFailureHandler(@Value("${app.frontend-url}") String frontendUrl) {
        this.failureRedirectUrl = UriComponentsBuilder.fromUriString(frontendUrl)
                .queryParam("authError", "access_denied")
                .build()
                .toUriString();
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        response.sendRedirect(failureRedirectUrl);
    }
}
