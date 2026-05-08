package com.sang.user_service.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * JWT utility class - handles token creation, parsing, and validation.
 *
 * HOW JWT WORKS:
 * 1. User logs in with email/password
 * 2. Server creates a JWT containing user info (claims) and signs it with a secret key
 * 3. Client stores the JWT and sends it in the Authorization header: "Bearer <token>"
 * 4. Server verifies the signature and extracts user info from the token
 *
 * JWT structure: HEADER.PAYLOAD.SIGNATURE
 * - Header:  {"alg": "HS256", "typ": "JWT"}
 * - Payload: {"sub": "user-id", "email": "...", "roles": [...], "exp": 1234567890}
 * - Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final SecretKey secretKey;
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;

    public JwtUtils(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration}") long accessTokenExpiration,
            @Value("${jwt.refresh-token-expiration}") long refreshTokenExpiration) {
        // Convert the secret string to a cryptographic key
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    /**
     * Generate an ACCESS token (short-lived, 15 min).
     * Contains user ID, email, and roles as claims.
     */
    public String generateAccessToken(UserDetailsImpl userDetails) {
        return buildToken(userDetails, accessTokenExpiration, "ACCESS");
    }

    /**
     * Generate a REFRESH token (long-lived, 7 days).
     * Used to get a new access token without re-entering credentials.
     */
    public String generateRefreshToken(UserDetailsImpl userDetails) {
        return buildToken(userDetails, refreshTokenExpiration, "REFRESH");
    }

    private String buildToken(UserDetailsImpl userDetails, long expiration, String tokenType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        // Extract role names from authorities
        List<String> roles = userDetails.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        return Jwts.builder()
                .subject(userDetails.getId().toString())          // "sub" claim = user ID
                .claim("email", userDetails.getEmail())           // custom claim
                .claim("username", userDetails.getUsername())      // custom claim
                .claim("roles", roles)                             // custom claim
                .claim("type", tokenType)                          // ACCESS or REFRESH
                .issuedAt(now)                                     // "iat" claim
                .expiration(expiryDate)                            // "exp" claim
                .signWith(secretKey)                               // sign with HMAC-SHA
                .compact();                                        // serialize to string
    }

    /**
     * Extract user ID from token.
     */
    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(getClaims(token).getSubject());
    }

    /**
     * Extract email from token.
     */
    public String getEmailFromToken(String token) {
        return getClaims(token).get("email", String.class);
    }

    /**
     * Extract token type (ACCESS or REFRESH).
     */
    public String getTokenType(String token) {
        return getClaims(token).get("type", String.class);
    }

    /**
     * Validate a JWT token - checks signature and expiration.
     */
    public boolean validateToken(String token) {
        try {
            getClaims(token); // This will throw if invalid
            return true;
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token expired: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.warn("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.warn("JWT claims string is empty: {}", e.getMessage());
        } catch (SecurityException e) {
            logger.warn("JWT signature validation failed: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Parse and verify the JWT, returning all claims.
     */
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)     // verify signature with our secret
                .build()
                .parseSignedClaims(token)  // parse and validate
                .getPayload();             // extract the claims (payload)
    }
}

