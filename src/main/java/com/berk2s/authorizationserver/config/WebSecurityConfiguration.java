package com.berk2s.authorizationserver.config;

import com.berk2s.authorizationserver.security.SecurityUserDetails;
import com.berk2s.authorizationserver.security.UserAuthenticationProvider;
import com.berk2s.authorizationserver.services.impl.SecurityUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserAuthenticationProvider userAuthenticationProvider;
    private final SecurityUserDetailsService securityUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(userAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .mvcMatchers("/authorize").authenticated()
                    .anyRequest().permitAll()
                .and()
                .formLogin()
                .and()
                .csrf().disable()
                .userDetailsService(securityUserDetailsService);
    }
}
