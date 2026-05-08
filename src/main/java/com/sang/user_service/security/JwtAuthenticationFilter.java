package com.sang.user_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

/**
 * JWT Authentication Filter - runs on EVERY request.
 *
 * FLOW:
 * 1. Extract JWT from "Authorization: Bearer <token>" header
 * 2. Validate the token (signature + expiration)
 * 3. Load user from DB
 * 4. Set authentication in SecurityContext (so Spring Security knows who the user is)
 *
 * This filter runs BEFORE Spring Security's default authentication filter.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // Step 1: Extract JWT from header
            String jwt = extractJwtFromRequest(request);

            // Step 2: Validate and process
            if (Objects.nonNull(jwt) && jwtUtils.validateToken(jwt)) {
                // Only accept ACCESS tokens (not REFRESH tokens)
                String tokenType = jwtUtils.getTokenType(jwt);
                if (!"ACCESS".equals(tokenType)) {
                    logger.warn("Non-access token used for authentication");
                    filterChain.doFilter(request, response);
                    return;
                }

                // Step 3: Load user details from DB
                String email = jwtUtils.getEmailFromToken(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                // Step 4: Create authentication token and set in SecurityContext
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,        // principal (the user)
                                null,               // credentials (not needed, already authenticated via JWT)
                                userDetails.getAuthorities()  // roles/permissions
                        );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Now Spring Security knows this user is authenticated for this request
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        // Continue the filter chain (pass to next filter or controller)
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT from "Authorization: Bearer <token>" header.
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7); // Remove "Bearer " prefix
        }

        return null;
    }
}

