package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.config.SecurityConfig;
import com.pareidolia.incidentmanagement.controller.AuthController;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationFailureHandler;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationSuccessHandler;
import com.pareidolia.incidentmanagement.security.GoogleWorkspaceOidcUserService;
import com.pareidolia.incidentmanagement.service.AppUserService;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Real application security filter chain, local MVC only: no database or Google calls.
@SpringJUnitWebConfig(AuthenticationFlowTests.Config.class)
class AuthenticationFlowTests {
    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, AuthController.class})
    static class Config {
        @Bean AppUserService users() { return mock(AppUserService.class); }
        @Bean GoogleWorkspaceOidcUserService oidcUsers() { return mock(GoogleWorkspaceOidcUserService.class); }
        @Bean GoogleAuthenticationSuccessHandler success(AppUserService users) {
            return new GoogleAuthenticationSuccessHandler(users, "http://frontend.test");
        }
        @Bean GoogleAuthenticationFailureHandler failure() {
            return new GoogleAuthenticationFailureHandler("http://frontend.test");
        }
        @Bean ClientRegistrationRepository registrations() {
            return new InMemoryClientRegistrationRepository(CommonOAuth2Provider.GOOGLE.getBuilder("google")
                    .clientId("test-client").clientSecret("test-secret").build());
        }
        @Bean OAuth2AuthorizedClientManager authorizedClientManager() {
            return mock(OAuth2AuthorizedClientManager.class);
        }
        @Bean OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient() {
            return mock(OAuth2AccessTokenResponseClient.class);
        }
    }

    @Autowired WebApplicationContext context;
    @Autowired @Qualifier("springSecurityFilterChain") Filter securityFilter;
    @Autowired GoogleAuthenticationSuccessHandler successHandler;
    @Autowired AppUserService users;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilter).build();
        reset(users);
    }

    private MockHttpSession authenticatedSession() {
        var session = new MockHttpSession();
        var authentication = new UsernamePasswordAuthenticationToken("reporter@example.test", null, List.of());
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(authentication));
        return session;
    }

    @Test
    void logoutInvalidatesApplicationSessionAndOldSessionCannotAuthenticate() throws Exception {
        var session = authenticatedSession();
        String oldId = session.getId();
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());
        var csrfResponse = mvc.perform(get("/api/auth/csrf").session(session))
                .andExpect(status().isOk()).andReturn().getResponse();
        var csrf = JsonMapper.builder().build().readTree(csrfResponse.getContentAsString());
        var csrfCookie = csrfResponse.getCookie("XSRF-TOKEN");
        var result = mvc.perform(post("/api/auth/logout").session(session).cookie(csrfCookie)
                        .header(csrf.get("headerName").asText(), csrf.get("token").asText()))
                .andExpect(status().isNoContent())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(cookie().maxAge("JSESSIONID", 0))
                .andExpect(cookie().maxAge("XSRF-TOKEN", 0)).andReturn();
        assertThat(session.isInvalid()).isTrue();
        assertThat(result.getRequest().getSession(false)).isNull();
        mvc.perform(get("/api/auth/me").cookie(new Cookie("JSESSIONID", oldId)))
                .andExpect(status().isUnauthorized()).andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/api/incidents").cookie(new Cookie("JSESSIONID", oldId)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRequiresValidCsrfAndGetDoesNotLogOut() throws Exception {
        var session = authenticatedSession();
        mvc.perform(post("/api/auth/logout").session(session)).andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/logout").session(session)
                .cookie(new Cookie("XSRF-TOKEN", "expected")).header("X-XSRF-TOKEN", "invalid"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/auth/logout").session(session)).andExpect(status().isNotFound());
        assertThat(session.isInvalid()).isFalse();
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isOk());
    }

    @Test
    void unauthenticatedApiRequestsReturn401WithoutStartingOAuth() throws Exception {
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/api/incidents")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk());
    }

    @Test
    void explicitAuthorizationRequestsAccountSelectionAndPreservesOAuthState() throws Exception {
        var result = mvc.perform(get("/oauth2/authorization/google"))
                .andExpect(status().is3xxRedirection()).andReturn();
        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect).startsWith("https://accounts.google.com/")
                .contains("prompt=select_account", "state=", "nonce=", "response_type=code", "client_id=test-client");
        assertThat(result.getRequest().getSession(false)).isNotNull();
    }

    @Test
    void successfulGoogleAuthenticationStillProvisionsUserAndReturnsToApplication() throws Exception {
        var principal = mock(OidcUser.class);
        var authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());
        var response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication);
        verify(users).provisionUser(principal);
        assertThat(response.getRedirectedUrl()).isEqualTo("http://frontend.test");
    }
}
