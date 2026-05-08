package com.sang.user_service.controller;

import com.sang.user_service.dto.request.LoginRequest;
import com.sang.user_service.dto.request.RefreshTokenRequest;
import com.sang.user_service.dto.request.RegisterRequest;
import com.sang.user_service.dto.request.Verify2FARequest;
import com.sang.user_service.dto.response.AuthResponse;
import com.sang.user_service.dto.response.MessageResponse;
import com.sang.user_service.dto.response.TwoFactorSetupResponse;
import com.sang.user_service.security.UserDetailsImpl;
import com.sang.user_service.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Auth Controller - REST endpoints for authentication.
 *
 * PUBLIC ENDPOINTS (no JWT needed):
 *   POST /api/auth/register   → create new account
 *   POST /api/auth/login      → login and get JWT tokens
 *   POST /api/auth/refresh    → get new access token using refresh token
 *
 * PROTECTED ENDPOINTS (JWT required):
 *   POST /api/auth/2fa/setup    → generate QR code for 2FA setup
 *   POST /api/auth/2fa/verify   → verify code and enable 2FA
 *   POST /api/auth/2fa/disable  → disable 2FA
 *   GET  /api/auth/me           → get current user info
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Register a new user.
     * POST /api/auth/register
     * Body: { "email": "...", "username": "...", "password": "...", ... }
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Login with email + password.
     * POST /api/auth/login
     * Body: { "email": "...", "password": "...", "twoFactorCode": "123456" }
     *
     * If 2FA is enabled and no code is provided, returns { twoFactorRequired: true }.
     * Client should then prompt for the code and resend the request with twoFactorCode.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, httpRequest));
    }

    /**
     * Get new access token using refresh token.
     * POST /api/auth/refresh
     * Body: { "refreshToken": "..." }
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.getRefreshToken()));
    }

    /**
     * Setup 2FA - generates QR code for the authenticator app.
     * POST /api/auth/2fa/setup
     * Requires: valid JWT (user must be logged in)
     */
    @PostMapping("/2fa/setup")
    public ResponseEntity<TwoFactorSetupResponse> setup2FA(
            @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return ResponseEntity.ok(authService.setup2FA(userDetails.getEmail()));
    }

    /**
     * Verify 2FA code and enable 2FA on the account.
     * POST /api/auth/2fa/verify
     * Body: { "code": "123456" }
     * Requires: valid JWT
     */
    @PostMapping("/2fa/verify")
    public ResponseEntity<MessageResponse> verify2FA(
            @AuthenticationPrincipal UserDetailsImpl userDetails,
            @Valid @RequestBody Verify2FARequest request) {
        authService.verify2FA(userDetails.getEmail(), request.getCode());
        return ResponseEntity.ok(new MessageResponse("2FA enabled successfully"));
    }

    /**
     * Disable 2FA.
     * POST /api/auth/2fa/disable
     * Requires: valid JWT
     */
    @PostMapping("/2fa/disable")
    public ResponseEntity<MessageResponse> disable2FA(
            @AuthenticationPrincipal UserDetailsImpl userDetails) {
        authService.disable2FA(userDetails.getEmail());
        return ResponseEntity.ok(new MessageResponse("2FA disabled successfully"));
    }

    /**
     * Get current authenticated user info.
     * GET /api/auth/me
     * Requires: valid JWT
     */
    @GetMapping("/me")
    public ResponseEntity<AuthResponse> getCurrentUser( 
            @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return ResponseEntity.ok(AuthResponse.builder()
                .email(userDetails.getEmail())
                .username(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream()
                        .map(Object::toString)
                        .toList())
                .twoFactorRequired(false)
                .build());
    }
}

