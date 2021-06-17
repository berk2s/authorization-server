package com.berk2s.authorizationserver.repository;

import com.berk2s.authorizationserver.domain.oauth.AuthorizationCode;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorizationCodeRepository extends CrudRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCode(String code);

    Optional<AuthorizationCode> findByCodeAndClientId(String code, String clientId);

    void deleteByCode(String code);

}
