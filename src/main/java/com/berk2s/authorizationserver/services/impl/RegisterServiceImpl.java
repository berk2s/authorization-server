package com.berk2s.authorizationserver.services.impl;

import com.berk2s.authorizationserver.domain.user.User;
import com.berk2s.authorizationserver.repository.UserRepository;
import com.berk2s.authorizationserver.security.RegisterService;
import com.berk2s.authorizationserver.web.exceptions.UserRegistrationException;
import com.berk2s.authorizationserver.web.models.ErrorDesc;
import com.berk2s.authorizationserver.web.models.RegisterRequestDto;
import com.berk2s.authorizationserver.web.models.RegisterResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class RegisterServiceImpl implements RegisterService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void register(RegisterRequestDto registerRequest) {
        String firstName = registerRequest.getFirstName();
        String lastName = registerRequest.getLastName();
        String email = registerRequest.getEmail();
        String phoneNumber = registerRequest.getPhoneNumber();
        String password = registerRequest.getPassword();

        if(userRepository.isPhoneNumberTaken(phoneNumber)) {
            log.warn("Given phone number is taken by another user [phoneNumber: {}]", phoneNumber);
            throw new UserRegistrationException(ErrorDesc.TAKEN_PHONE_NUMBER.getDesc());
        }

        if(userRepository.isEmailTaken(email)) {
            log.warn("Given email is taken by another user [email: {}]", email);
            throw new UserRegistrationException(ErrorDesc.TAKEN_EMAIL.getDesc());
        }

        String username = generateUsername(firstName, lastName);

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmail(email);
        user.setPhoneNumber(phoneNumber);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(true);
        user.setCredentialsNonExpired(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);

        userRepository.save(user);

        log.info("User has been created [userId: {}]", user.getId());
    }

    private String generateUsername(String firstName, String lastName) {
        String generatedUsername = firstName.trim() + lastName.trim() + RandomUtils.nextInt(999,999999);

        if(userRepository.isUsernameTaken(generatedUsername)) {
            generateUsername(firstName, lastName);
        }

        return generatedUsername;
    }



}
