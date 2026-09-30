package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.AuthenticatedUserResponseDto;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AppUserService {

    private final AppUserRepository appUserRepository;
    private final Set<String> bootstrapAdminEmails;
    private final Set<String> bootstrapItHandlerEmails;

    public AppUserService(
            AppUserRepository appUserRepository,
            @Value("${app.auth.bootstrap-admin-emails}") String configuredBootstrapAdminEmails,
            @Value("${app.auth.bootstrap-it-handler-emails}") String configuredBootstrapItHandlerEmails
    ) {
        this.appUserRepository = appUserRepository;
        this.bootstrapAdminEmails = parseConfiguredEmails(configuredBootstrapAdminEmails);
        this.bootstrapItHandlerEmails = parseConfiguredEmails(configuredBootstrapItHandlerEmails);
    }

    @Transactional
    public AppUser provisionUser(OidcUser oidcUser) {
        String email = normalizeEmail(oidcUser.getEmail());
        if (email.isEmpty()) {
            throw new IllegalStateException("Google account email is unavailable.");
        }

        AppUser appUser = appUserRepository.findByEmail(email).orElseGet(AppUser::new);
        appUser.setEmail(email);
        appUser.setDisplayName(resolveDisplayName(oidcUser, email));
        appUser.setActive(Boolean.TRUE);
        appUser.setLastLoginAt(LocalDateTime.now());
        if (appUser.getRole() == null) {
            appUser.setRole(AppUserRole.REPORTER);
        }
        if (bootstrapAdminEmails.contains(email)) {
            appUser.setRole(AppUserRole.ADMIN);
        } else if (bootstrapItHandlerEmails.contains(email)
                && appUser.getRole() != AppUserRole.ADMIN) {
            appUser.setRole(AppUserRole.IT_HANDLER);
        }
        return appUserRepository.save(appUser);
    }

    @Transactional(readOnly = true)
    public AuthenticatedUserResponseDto getAuthenticatedUserResponse() {
        return toResponse(getAuthenticatedUser());
    }

    @Transactional(readOnly = true)
    public AppUser getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || !(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
            throw new AccessDeniedException("Authentication is required.");
        }

        return appUserRepository.findByEmail(normalizeEmail(oidcUser.getEmail()))
                .orElseThrow(() -> new AccessDeniedException("Authenticated application user was not found."));
    }

    private AuthenticatedUserResponseDto toResponse(AppUser appUser) {
        AuthenticatedUserResponseDto response = new AuthenticatedUserResponseDto();
        response.setEmail(appUser.getEmail());
        response.setDisplayName(appUser.getDisplayName());
        response.setRole(appUser.getRole());
        return response;
    }

    private String resolveDisplayName(OidcUser oidcUser, String email) {
        String displayName = oidcUser.getFullName();
        return displayName == null || displayName.isBlank() ? email : displayName;
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private Set<String> parseConfiguredEmails(String configuredEmails) {
        return Arrays.stream(configuredEmails.split(","))
                .map(this::normalizeEmail)
                .filter(email -> !email.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
