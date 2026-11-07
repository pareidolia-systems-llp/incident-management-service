package com.pareidolia.incidentmanagement.security;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.service.AppUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class EmployeeManagementAccess {
    private final boolean enabled;
    private final Set<String> emails;
    public EmployeeManagementAccess(Environment environment,
            @Value("${app.employee-management.enabled:false}") boolean enabled,
            @Value("${app.employee-management.allowed-emails:}") String emails) {
        boolean dev = environment.acceptsProfiles(Profiles.of("dev"));
        boolean production = environment.acceptsProfiles(Profiles.of("prod", "production"));
        boolean test = environment.acceptsProfiles(Profiles.of("test"));
        boolean productionApproved = environment.getProperty("app.employee-management.production-enabled", Boolean.class, false);
        boolean defaultOnly = environment.getActiveProfiles().length == 0 && java.util.Arrays.equals(environment.getDefaultProfiles(), new String[]{"default"});
        this.enabled = enabled && ((dev && !production) || (!dev && !test && (production || defaultOnly) && productionApproved));
        this.emails = Arrays.stream(emails.split(",")).map(AppUserService::normalizeEmail)
                .filter(email -> !email.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
    public boolean canManage(AppUser user) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return enabled && user != null && Boolean.TRUE.equals(user.getActive())
                && auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof OidcUser oidc
                && Boolean.TRUE.equals(oidc.getEmailVerified())
                && AppUserService.normalizeEmail(oidc.getEmail()).equals(AppUserService.normalizeEmail(user.getEmail()))
                && emails.contains(AppUserService.normalizeEmail(user.getEmail()));
    }
}
