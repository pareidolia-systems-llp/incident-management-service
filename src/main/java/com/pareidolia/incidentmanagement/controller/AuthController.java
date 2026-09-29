package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.dto.AuthenticatedUserResponseDto;
import com.pareidolia.incidentmanagement.service.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AppUserService appUserService;

    @GetMapping("/csrf")
    public CsrfToken csrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @GetMapping("/me")
    public AuthenticatedUserResponseDto currentUser(@AuthenticationPrincipal OidcUser oidcUser) {
        return appUserService.getCurrentUser(oidcUser.getEmail());
    }
}
