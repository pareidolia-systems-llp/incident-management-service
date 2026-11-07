package com.pareidolia.incidentmanagement.assignment;

import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.repository.AppUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class EmployeeDirectoryQueryTests {
    @Autowired AppUserRepository users;

    @Test void searchesOnlyActiveEmailsIgnoringCaseAndHonorsTheBound() {
        save("one@example.test", true);
        save("two@example.test", true);
        save("inactive@example.test", false);
        var all = users.findByActiveTrueAndEmailContainingIgnoreCase("EXAMPLE.TEST", PageRequest.of(0, 10));
        assertThat(all.getContent()).extracting(AppUser::getEmail)
            .containsExactlyInAnyOrder("one@example.test", "two@example.test");
        assertThat(users.findByActiveTrueAndEmailContainingIgnoreCase("example.test", PageRequest.of(0, 1))
            .getContent()).hasSize(1);
    }
    private void save(String email, boolean active) {
        var user = new AppUser();
        user.setEmail(email);
        user.setDisplayName(email);
        user.setActive(active);
        users.saveAndFlush(user);
    }
}
