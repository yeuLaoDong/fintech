package com.sang.user_service.config;

import com.sang.user_service.security.JwtAuthEntryPoint;
import com.sang.user_service.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security Configuration - the heart of Spring Security setup.
 *
 * KEY CONCEPTS:
 * - SecurityFilterChain: defines which URLs are public vs protected
 * - AuthenticationManager: handles login (email + password verification)
 * - PasswordEncoder: hashes passwords with BCrypt (never store plain text!)
 * - SessionCreationPolicy.STATELESS: no server-side sessions, JWT handles state
 * - JwtAuthenticationFilter: custom filter that validates JWT on every request
 */
@Configuration
@EnableWebSecurity       // Enable Spring Security
@EnableMethodSecurity    // Enable @PreAuthorize, @Secured on methods
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthEntryPoint jwtAuthEntryPoint;
    private final UserDetailsService userDetailsService;

    /**
     * The main security configuration.
     * Defines which endpoints are public and which require authentication.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF - not needed for stateless JWT APIs
            .csrf(AbstractHttpConfigurer::disable)

            // Handle unauthorized access with our custom entry point
            .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthEntryPoint))

            // STATELESS = no HTTP session. Each request must carry a JWT.
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // URL-based authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints - no JWT needed
                .requestMatchers(
                    "/api/auth/**",         // login, register, refresh
                    "/api/public/**",       // any public endpoints
                    "/v3/api-docs/**",      // Swagger (future)
                    "/swagger-ui/**",       // Swagger UI (future)
                    "/error"                // Spring Boot error endpoint
                ).permitAll()

                // Admin-only endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // Everything else requires authentication
                .anyRequest().authenticated()
            )

            // Set our custom authentication provider
            .authenticationProvider(authenticationProvider())

            // Add JWT filter BEFORE Spring's default username/password filter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * DaoAuthenticationProvider - authenticates users against the database.
     * Uses UserDetailsService to load user and PasswordEncoder to verify password.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * AuthenticationManager - Spring Security's main authentication interface.
     * Used in AuthService to authenticate login requests.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * BCrypt password encoder - industry standard for password hashing.
     * BCrypt automatically salts passwords and is resistant to brute-force attacks.
     * Strength 12 = 2^12 = 4096 rounds of hashing.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}


