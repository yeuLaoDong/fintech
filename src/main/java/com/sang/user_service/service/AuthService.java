package com.sang.user_service.service;

import com.sang.user_service.dto.request.LoginRequest;
import com.sang.user_service.dto.request.RegisterRequest;
import com.sang.user_service.dto.response.AuthResponse;
import com.sang.user_service.dto.response.TwoFactorSetupResponse;
import com.sang.user_service.entity.Role;
import com.sang.user_service.entity.User;
import com.sang.user_service.entity.UserStatus;
import com.sang.user_service.repository.RoleRepository;
import com.sang.user_service.repository.UserRepository;
import com.sang.user_service.security.JwtUtils;
import com.sang.user_service.security.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

/**
 * Authentication Service - handles all auth business logic.
 *
 * REGISTRATION FLOW:
 * 1. Validate input → check email/username uniqueness
 * 2. Hash password with BCrypt
 * 3. Assign ROLE_USER
 * 4. Save to DB with status ACTIVE
 *
 * LOGIN FLOW:
 * 1. AuthenticationManager verifies email + password against DB
 * 2. Check if account is locked (brute-force protection)
 * 3. If 2FA enabled → require TOTP code
 * 4. Reset failed attempts, update last login info
 * 5. Generate access + refresh JWT tokens
 *
 * REFRESH FLOW:
 * 1. Validate refresh token (signature + expiration + type=REFRESH)
 * 2. Load user, generate new access token
 *
 * 2FA SETUP FLOW:
 * 1. Generate TOTP secret
 * 2. Generate QR code for authenticator app
 * 3. User scans QR, enters code to verify
 * 4. If valid → enable 2FA on account
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 30;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final TotpService totpService;

    /**
     * Register a new user.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Check uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already taken");
        }

        // Find the default role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role ROLE_USER not found"));

        // Build user entity
        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))  // Hash password!
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .status(UserStatus.ACTIVE)   // In production, use PENDING + email verification
                .roles(Set.of(userRole))
                .build();

        userRepository.save(user);
        logger.info("New user registered: {}", user.getEmail());

        // Auto-login after registration
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String accessToken = jwtUtils.generateAccessToken(userDetails);
        String refreshToken = jwtUtils.generateRefreshToken(userDetails);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(List.of("ROLE_USER"))
                .twoFactorRequired(false)
                .build();
    }

    /**
     * Login with email + password (+ optional 2FA code).
     */
    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        // Step 1: Find user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        // Step 2: Check if account is locked
        if (user.isAccountLocked()) {
            throw new RuntimeException("Account is locked. Try again after " + user.getLockedUntil());
        }

        // Step 3: Verify password via AuthenticationManager
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            // Wrong password → increment failed attempts
            handleFailedLogin(user);
            throw new RuntimeException("Invalid email or password");
        }

        // Step 4: Check 2FA
        if (user.isTwoFactorEnabled()) {
            if (request.getTwoFactorCode() == null || request.getTwoFactorCode().isBlank()) {
                // Password correct but 2FA code not provided → tell client to ask for it
                return AuthResponse.builder()
                        .twoFactorRequired(true)
                        .email(user.getEmail())
                        .build();
            }

            // Verify TOTP code
            if (!totpService.verifyCode(user.getTwoFactorSecret(), request.getTwoFactorCode())) {
                throw new RuntimeException("Invalid 2FA code");
            }
        }

        // Step 5: Login success → reset failed attempts, update login info
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(getClientIp(httpRequest));
        userRepository.save(user);

        // Step 6: Generate tokens
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String accessToken = jwtUtils.generateAccessToken(userDetails);
        String refreshToken = jwtUtils.generateRefreshToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(roles)
                .twoFactorRequired(false)
                .build();
    }

    /**
     * Refresh access token using a valid refresh token.
     */
    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtUtils.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (!"REFRESH".equals(jwtUtils.getTokenType(refreshToken))) {
            throw new RuntimeException("Token is not a refresh token");
        }

        String email = jwtUtils.getEmailFromToken(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String newAccessToken = jwtUtils.generateAccessToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)  // Return same refresh token
                .tokenType("Bearer")
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(roles)
                .twoFactorRequired(false)
                .build();
    }

    /**
     * Step 1 of 2FA setup: generate secret + QR code.
     */
    @Transactional
    public TwoFactorSetupResponse setup2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.isTwoFactorEnabled()) {
            throw new RuntimeException("2FA is already enabled");
        }

        // Generate and save secret
        String secret = totpService.generateSecret();
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        // Generate QR code
        String qrCodeUri = totpService.generateQrCodeUri(secret, email);

        return TwoFactorSetupResponse.builder()
                .secret(secret)
                .qrCodeUri(qrCodeUri)
                .build();
    }

    /**
     * Step 2 of 2FA setup: verify the code from the authenticator app and enable 2FA.
     */
    @Transactional
    public void verify2FA(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getTwoFactorSecret() == null) {
            throw new RuntimeException("2FA setup not initiated. Call setup first.");
        }

        if (!totpService.verifyCode(user.getTwoFactorSecret(), code)) {
            throw new RuntimeException("Invalid 2FA code. Please try again.");
        }

        // Code is valid → enable 2FA
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        logger.info("2FA enabled for user: {}", email);
    }

    /**
     * Disable 2FA for a user.
     */
    @Transactional
    public void disable2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
        logger.info("2FA disabled for user: {}", email);
    }

    // ========== HELPER METHODS ==========

    /**
     * Handle failed login: increment attempts, lock account if too many failures.
     */
    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(Instant.now().plus(LOCK_DURATION_MINUTES, ChronoUnit.MINUTES));
            logger.warn("Account locked for user: {} after {} failed attempts", user.getEmail(), attempts);
        }

        userRepository.save(user);
    }

    /**
     * Extract client IP address from request (handles proxies).
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

