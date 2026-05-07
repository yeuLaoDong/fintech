package com.sang.user_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorSetupResponse {

    /**
     * The secret key (base32 encoded) - user can manually enter this in their authenticator app.
     */
    private String secret;

    /**
     * QR code image as a data URI (data:image/png;base64,...).
     * User scans this with Google Authenticator, Authy, etc.
     */
    private String qrCodeUri;
}

