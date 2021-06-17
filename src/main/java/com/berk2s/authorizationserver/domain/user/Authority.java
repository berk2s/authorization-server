package com.berk2s.authorizationserver.domain;

import lombok.*;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class Authority extends BaseEntity{

    @Column(name = "authority_name", unique = true)
    private String authorityName;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "USER_AUTHORITIES",
            joinColumns = {
                @JoinColumn(name = "authority_id", referencedColumnName = "id")
            }, inverseJoinColumns = {
            @JoinColumn(name = "user_id", referencedColumnName = "id")
    })
    private Set<User> users = new HashSet<>();

    public void addUsers(User user) {
        user.getAuthorities().add(this);
        users.add(user);
    }

}
