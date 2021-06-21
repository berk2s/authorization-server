package com.berk2s.authorizationserver.security;

import com.berk2s.authorizationserver.domain.user.User;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

public class SecurityUserDetails extends SecurityDetails implements UserDetails {

    private final User user;

    public SecurityUserDetails(User user) {
        super(user);
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        user.getAuthorities().stream()
                .map(a -> grantedAuthorities.add(new SimpleGrantedAuthority(a.getAuthorityName().toUpperCase(Locale.ROOT))))
                .close();

        user.getRoles().stream()
                .map(r -> grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + r.getRoleName().toUpperCase(Locale.ROOT))))
                .close();

        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    public UUID getId() {
        return user.getId();
    }

    public String getName() {
        return user.getFirstName();
    }

    public String getLastName() {
        return user.getLastName();
    }

    public String getEmail() {
        return user.getEmail();
    }


}
