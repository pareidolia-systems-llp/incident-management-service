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
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.IncidentSecurityGate securityGate;
    @org.springframework.beans.factory.annotation.Value("${app.incident-access.enabled:false}") private boolean securityGateEnabled;
    private void securityWrite(){
        if(securityGateEnabled){if(securityGate==null)throw new IllegalStateException("Security gate unavailable.");securityGate.write();}
    }
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.pareidolia.incidentmanagement.security.EmployeeManagementAccess employeeAccess;
    @org.springframework.beans.factory.annotation.Autowired(required=false) private jakarta.persistence.EntityManager securityEntityManager;
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
        securityWrite();
        String email = normalizeEmail(oidcUser.getEmail());
        if (email.isEmpty()) {
            throw new IllegalStateException("Google account email is unavailable.");
        }

        AppUser appUser = appUserRepository.findByEmailForUpdate(email).orElseGet(AppUser::new);
        if(securityGateEnabled && appUser.getId()!=null){if(securityEntityManager==null)throw new IllegalStateException("Security persistence unavailable.");securityEntityManager.refresh(appUser,jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);}
        if (!Boolean.TRUE.equals(appUser.getActive())) {
            throw new AccessDeniedException("Account is inactive.");
        }
        appUser.setEmail(email);
        if (appUser.getId() == null) appUser.setDisplayName(resolveDisplayName(oidcUser, email));
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

        AppUser user = appUserRepository.findByEmail(normalizeEmail(oidcUser.getEmail()))
                .orElseThrow(() -> new AccessDeniedException("Authenticated application user was not found."));
        if (!Boolean.TRUE.equals(user.getActive())) throw new AccessDeniedException("Account is inactive.");
        return user;
    }

    private AuthenticatedUserResponseDto toResponse(AppUser appUser) {
        AuthenticatedUserResponseDto response = new AuthenticatedUserResponseDto();
        response.setEmail(appUser.getEmail());
        response.setDisplayName(appUser.getDisplayName());
        response.setRole(appUser.getRole());
        response.setCanManageEmployees(employeeAccess != null && employeeAccess.canManage(appUser));
        return response;
    }

    private String resolveDisplayName(OidcUser oidcUser, String email) {
        String displayName = oidcUser.getFullName();
        return displayName == null || displayName.isBlank() ? email : displayName;
    }

    public static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private Set<String> parseConfiguredEmails(String configuredEmails) {
        return Arrays.stream(configuredEmails.split(","))
                .map(AppUserService::normalizeEmail)
                .filter(email -> !email.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
