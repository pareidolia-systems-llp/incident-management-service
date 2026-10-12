package com.pareidolia.incidentmanagement.repository;

import com.pareidolia.incidentmanagement.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    java.util.List<AppUser> findByEmailIn(java.util.Collection<String> emails);

    Optional<AppUser> findByEmail(String email);
}
