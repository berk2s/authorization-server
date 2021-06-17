package com.berk2s.authorizationserver.repository;

import com.berk2s.authorizationserver.domain.oauth.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ClientRepository extends JpaRepository<Client, UUID> {

    Optional<Client> findByClientId(String clientId);

}
