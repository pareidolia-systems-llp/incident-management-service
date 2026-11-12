package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.config.SecurityConfig;
import com.pareidolia.incidentmanagement.controller.AuthController;
import com.pareidolia.incidentmanagement.controller.WorkLogController;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.repository.WorkLogRepository;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationFailureHandler;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationSuccessHandler;
import com.pareidolia.incidentmanagement.security.GoogleWorkspaceOidcUserService;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.WorkLogService;
import com.pareidolia.incidentmanagement.service.impl.WorkLogServiceImpl;
import jakarta.servlet.Filter;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(DeactivatedSessionHttpTests.Config.class)
class DeactivatedSessionHttpTests {
    @TestConfiguration @EnableWebMvc
    @Import({SecurityConfig.class, AuthController.class, WorkLogController.class})
    static class Config {
        @Bean AppUserRepository accounts() { return mock(AppUserRepository.class); }
        @Bean WorkLogRepository workLogs() { return mock(WorkLogRepository.class); }
        @Bean AppUserService users(AppUserRepository accounts) { return new AppUserService(accounts, "", ""); }
        @Bean WorkLogService workLogService(AppUserService users, WorkLogRepository logs) { return new WorkLogServiceImpl(users, logs); }
        @Bean GoogleWorkspaceOidcUserService oidcUsers() { return mock(GoogleWorkspaceOidcUserService.class); }
        @Bean GoogleAuthenticationSuccessHandler success(AppUserService users) { return new GoogleAuthenticationSuccessHandler(users, "http://frontend.test"); }
        @Bean GoogleAuthenticationFailureHandler failure() { return new GoogleAuthenticationFailureHandler("http://frontend.test"); }
        @Bean ClientRegistrationRepository registrations() { return new InMemoryClientRegistrationRepository(CommonOAuth2Provider.GOOGLE.getBuilder("google").clientId("synthetic").clientSecret("synthetic").build()); }
        @Bean OAuth2AuthorizedClientManager manager() { return mock(OAuth2AuthorizedClientManager.class); }
        @Bean OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient() { return mock(OAuth2AccessTokenResponseClient.class); }
    }
    @Autowired WebApplicationContext context;
    @Autowired @Qualifier("springSecurityFilterChain") Filter filter;
    @Autowired AppUserRepository accounts;
    @Autowired WorkLogRepository workLogs;

    @Test void previouslyAuthenticatedSessionLosesDirectApiAccessAfterDeactivation() throws Exception {
        var user=new AppUser(); user.setId(42L); user.setEmail("synthetic@example.test"); user.setRole(AppUserRole.IT_HANDLER); user.setActive(true);
        when(accounts.findByEmail("synthetic@example.test")).thenAnswer(inv -> Optional.of(user));
        var oidc=mock(OidcUser.class); when(oidc.getEmail()).thenReturn("synthetic@example.test"); when(oidc.getEmailVerified()).thenReturn(true);
        var session=new MockHttpSession(); session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(new UsernamePasswordAuthenticationToken(oidc,null,List.of())));
        var mvc=MockMvcBuilders.webAppContextSetup(context).addFilters(filter).build();
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());
        user.setActive(false);
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isForbidden());
        mvc.perform(get("/api/work-logs").session(session)).andExpect(status().isForbidden());
        verifyNoInteractions(workLogs);
    }

    @Test void loginCannotReactivateAnInactiveBootstrapAccount() {
        var repo=mock(AppUserRepository.class); var user=new AppUser();
        user.setEmail("former@example.test"); user.setRole(AppUserRole.IT_HANDLER); user.setActive(false);
        var oidc=mock(OidcUser.class); when(oidc.getEmail()).thenReturn(user.getEmail());
        when(repo.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        var service=new AppUserService(repo, user.getEmail(), "");
        assertThatThrownBy(()->service.provisionUser(oidc)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        verify(repo, never()).save(any());
    }
}
