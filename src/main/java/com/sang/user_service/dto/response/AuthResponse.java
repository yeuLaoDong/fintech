package com.sang.user_service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private String email;
    private String username;
    private List<String> roles;

    /**
     * If true, user must provide 2FA code before getting tokens.
     * In that case, accessToken and refreshToken will be null.
     */
    private boolean twoFactorRequired;
}

