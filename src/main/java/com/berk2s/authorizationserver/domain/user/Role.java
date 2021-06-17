package com.berk2s.authorizationserver.domain;

import com.berk2s.authorizationserver.domain.user.BaseEntity;
import com.berk2s.authorizationserver.domain.user.User;
import lombok.*;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Role extends BaseEntity {

    @Column(name = "role_name", unique = true)
    public String roleName;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = {
                @JoinColumn(name = "group_id", referencedColumnName = "id")
            },
            inverseJoinColumns = {
                @JoinColumn(name = "user_id", referencedColumnName = "id")
            })
    private Set<User> users = new HashSet<>();

    public void addUser(User user) {
        user.getRoles().add(this);
        users.add(user);
    }

}
