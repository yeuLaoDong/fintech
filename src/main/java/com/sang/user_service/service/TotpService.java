package com.sang.user_service.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * TOTP (Time-based One-Time Password) Service for 2FA.
 *
 * HOW TOTP WORKS:
 * 1. Server generates a secret key and shares it with user (via QR code)
 * 2. User adds it to Google Authenticator / Authy
 * 3. Both server and app generate a 6-digit code every 30 seconds using:
 *    CODE = HMAC-SHA1(secret, current_time / 30) → truncate to 6 digits
 * 4. On login, user enters the code, server verifies it matches
 *
 * The secret is shared once, then both sides can independently generate codes.
 * No network connection needed on the authenticator app.
 */
@Service
public class TotpService {

    @Value("${totp.issuer}")
    private String issuer;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();

    /**
     * Generate a new TOTP secret (base32 encoded).
     * This is stored in the user's DB record.
     */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /**
     * Generate a QR code data URI that the user scans with their authenticator app.
     * The QR code contains: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
     */
    public String generateQrCodeUri(String secret, String email) {
        QrData qrData = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)  // Standard TOTP uses SHA1
                .digits(6)                          // 6-digit codes
                .period(30)                         // New code every 30 seconds
                .build();

        try {
            byte[] qrCodeImage = qrGenerator.generate(qrData);
            return Utils.getDataUriForImage(qrCodeImage, qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    /**
     * Verify the 6-digit TOTP code entered by the user.
     * Allows ±1 time period (30 sec) tolerance to handle clock skew.
     */
    public boolean verifyCode(String secret, String code) {
        CodeVerifier verifier = new DefaultCodeVerifier(
                new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6),
                timeProvider
        );

        // Allow 1 period before/after current time (handles slight clock differences)
        ((DefaultCodeVerifier) verifier).setAllowedTimePeriodDiscrepancy(1);

        return verifier.isValidCode(secret, code);
    }
}

