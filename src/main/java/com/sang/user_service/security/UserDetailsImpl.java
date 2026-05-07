package com.sang.user_service.security;

import com.sang.user_service.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Adapter between our User entity and Spring Security's UserDetails.
 * Spring Security uses this to check credentials, roles, and account status.
 */
@AllArgsConstructor
@Getter
public class UserDetailsImpl implements UserDetails {

    private final UUID id;
    private final String email;
    private final String username;
    private final String password;
    private final boolean active;
    private final boolean accountLocked;
    private final boolean twoFactorEnabled;
    private final Collection<? extends GrantedAuthority> authorities;

    /**
     * Factory method: converts our User entity → Spring Security UserDetails
     */
    public static UserDetailsImpl build(User user) {
        // Convert Role entities to GrantedAuthority (what Spring Security understands)
        var authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toSet());

        return new UserDetailsImpl(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getPassword(),
                user.isActive(),
                user.isAccountLocked(),
                user.isTwoFactorEnabled(),
                authorities
        );
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // We don't expire accounts
    }

    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked; // Locked if too many failed login attempts
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // We don't expire passwords (yet)
    }

    @Override
    public boolean isEnabled() {
        return active; // Only ACTIVE users can login
    }
}

