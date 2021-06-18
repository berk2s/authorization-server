package com.berk2s.authorizationserver.repository;

import com.berk2s.authorizationserver.domain.user.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
}
