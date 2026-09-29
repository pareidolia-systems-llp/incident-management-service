package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.AuthenticatedUserResponseDto;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
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

    public AppUserService(
            AppUserRepository appUserRepository,
            @Value("${app.auth.bootstrap-admin-emails}") String configuredBootstrapAdminEmails
    ) {
        this.appUserRepository = appUserRepository;
        this.bootstrapAdminEmails = Arrays.stream(configuredBootstrapAdminEmails.split(","))
                .map(this::normalizeEmail)
                .filter(email -> !email.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
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
        }
        return appUserRepository.save(appUser);
    }

    @Transactional(readOnly = true)
    public AuthenticatedUserResponseDto getCurrentUser(String rawEmail) {
        AppUser appUser = appUserRepository.findByEmail(normalizeEmail(rawEmail))
                .orElseThrow(() -> new IllegalStateException("Authenticated application user was not found."));

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
}
