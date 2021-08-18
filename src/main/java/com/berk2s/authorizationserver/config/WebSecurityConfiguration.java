package com.berk2s.authorizationserver.config;

import com.berk2s.authorizationserver.security.*;
import com.berk2s.authorizationserver.services.JWTService;
import com.berk2s.authorizationserver.services.impl.SecurityUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserAuthenticationProvider userAuthenticationProvider;
    private final SecurityUserDetailsService securityUserDetailsService;
    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final BeforeSecuredRequestFilter beforeSecuredRequestFilter;
    private final JwtDecoder jwtDecoder;

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
                .oauth2ResourceServer(oauth2 -> oauth2.jwt()
                    .jwtAuthenticationConverter(getJwtAuthenticationConverter()))
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

    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

            for (String authority : jwt.getClaimAsStringList("scopes")) {
                grantedAuthorities.add(
                        new SimpleGrantedAuthority(authority.toUpperCase(Locale.ROOT)));
            }

            for (String role : jwt.getClaimAsStringList("roles")) {
                grantedAuthorities.add(
                        new SimpleGrantedAuthority("ROLE_" + role.toUpperCase(Locale.ROOT)));
            }

            return grantedAuthorities;
        });

        return converter;
    }

}
