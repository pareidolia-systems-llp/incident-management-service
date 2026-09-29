package com.pareidolia.incidentmanagement.config;

import com.pareidolia.incidentmanagement.security.GoogleAuthenticationFailureHandler;
import com.pareidolia.incidentmanagement.security.GoogleAuthenticationSuccessHandler;
import com.pareidolia.incidentmanagement.security.GoogleWorkspaceOidcUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            GoogleWorkspaceOidcUserService googleWorkspaceOidcUserService,
            GoogleAuthenticationSuccessHandler googleAuthenticationSuccessHandler,
            GoogleAuthenticationFailureHandler googleAuthenticationFailureHandler,
            OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository
    ) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth2/**", "/login/**", "/api/auth/csrf").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                PathPatternRequestMatcher.pathPattern("/api/**")
                        )
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizedClientRepository(oauth2AuthorizedClientRepository)
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(googleWorkspaceOidcUserService))
                        .successHandler(googleAuthenticationSuccessHandler)
                        .failureHandler(googleAuthenticationFailureHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID", "XSRF-TOKEN")
                        .logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_NO_CONTENT))
                );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository() {
        return new OAuth2AuthorizedClientRepository() {
            @Override
            public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
                    String clientRegistrationId,
                    Authentication principal,
                    HttpServletRequest request
            ) {
                return null;
            }

            @Override
            public void saveAuthorizedClient(
                    OAuth2AuthorizedClient authorizedClient,
                    Authentication principal,
                    HttpServletRequest request,
                    HttpServletResponse response
            ) {
                // This application does not make Google API calls or persist OAuth access tokens.
            }

            @Override
            public void removeAuthorizedClient(
                    String clientRegistrationId,
                    Authentication principal,
                    HttpServletRequest request,
                    HttpServletResponse response
            ) {
                // No OAuth authorized client is retained after login.
            }
        };
    }
}
