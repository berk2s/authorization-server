package com.berk2s.authorizationserver.repository;

import com.berk2s.authorizationserver.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByPhoneNumber(String phoneNumber);

    @Query("select count(u)>0 from USERS u where u.phoneNumber = ?1 or u.email = ?2")
    boolean isUserExists(String phoneNumber, String email);

    @Query("select count(u)>0 from USERS u where u.username = ?1")
    boolean isUsernameTaken(String username);

    @Query("select count(u)>0 from USERS u where u.phoneNumber = ?1")
    boolean isPhoneNumberTaken(String phoneNumber);

    @Query("select count(u)>0 from USERS u where u.email = ?1")
    boolean isEmailTaken(String email);

}
