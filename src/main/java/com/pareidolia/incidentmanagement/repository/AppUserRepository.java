package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    java.util.List<AppUser> findByEmailIn(java.util.Collection<String> emails);

    Optional<AppUser> findByEmail(String email);

    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select u from AppUser u where u.email = :email")
    Optional<AppUser> findByEmailForUpdate(@org.springframework.data.repository.query.Param("email") String email);

    // Internal directory building block only. Active status is not eligibility.
    org.springframework.data.domain.Page<AppUser> findByActiveTrueAndEmailContainingIgnoreCase(
            String email, org.springframework.data.domain.Pageable pageable);
}
