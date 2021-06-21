package com.berk2s.authorizationserver.config;

import com.berk2s.authorizationserver.security.*;
import com.berk2s.authorizationserver.services.impl.SecurityUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserAuthenticationProvider userAuthenticationProvider;
    private final SecurityUserDetailsService securityUserDetailsService;
    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final BeforeSecuredRequestFilter beforeSecuredRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(userAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(beforeSecuredRequestFilter,
                        BasicAuthenticationFilter.class)
                .authorizeRequests()
                    .mvcMatchers("/authorize").authenticated()
                    .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/sign-in")
                .loginProcessingUrl("/login")
                .failureHandler(loginFailureHandler)
                .usernameParameter("username")
                .passwordParameter("password")
                .and()
                .csrf().disable()
                .userDetailsService(securityUserDetailsService);
    }
}
