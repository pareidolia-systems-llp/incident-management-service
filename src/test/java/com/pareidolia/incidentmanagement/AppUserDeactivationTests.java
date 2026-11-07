package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import com.pareidolia.incidentmanagement.service.AppUserService;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AppUserDeactivationTests {
    @Test void loginDoesNotReactivateOrSaveDisabledAccount() {
        var repo=mock(AppUserRepository.class); var oidc=mock(OidcUser.class);
        var user=new AppUser(); user.setEmail("disabled@example.test"); user.setDisplayName("Disabled"); user.setActive(false);
        when(oidc.getEmail()).thenReturn("disabled@example.test"); when(repo.findByEmailForUpdate("disabled@example.test")).thenReturn(Optional.of(user));
        var service=new AppUserService(repo,"","");
        assertThatThrownBy(() -> service.provisionUser(oidc)).isInstanceOf(AccessDeniedException.class);
        assertThat(user.getActive()).isFalse(); verify(repo,never()).save(any());
    }
    @Test void newAccountRemainsProvisionable() {
        var repo=mock(AppUserRepository.class); var oidc=mock(OidcUser.class);
        when(oidc.getEmail()).thenReturn("new@example.test"); when(repo.findByEmailForUpdate("new@example.test")).thenReturn(Optional.empty());
        when(repo.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));
        var user=new AppUserService(repo,"","").provisionUser(oidc);
        assertThat(user.getActive()).isTrue(); assertThat(user.getEmail()).isEqualTo("new@example.test");
    }
}
