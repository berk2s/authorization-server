package com.berk2s.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.util.IdGenerator;
import org.springframework.util.JdkIdGenerator;

@Component
public class IdGeneratorConfiguration {

    @Bean
    IdGenerator idGenerator() {
        return new JdkIdGenerator();
    }

}
