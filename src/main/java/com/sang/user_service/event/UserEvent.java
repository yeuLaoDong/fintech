package com.sang.user_service.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * User Event - sent to Kafka for other services (notification-service, account-service, etc.)
 *
 * Event types:
 *   USER_REGISTERED  → notification-service sends welcome email
 *   USER_LOGIN       → notification-service can send login alert
 *   USER_LOCKED      → notification-service sends account locked warning
 *   USER_2FA_ENABLED → notification-service sends 2FA confirmation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEvent {

    private String eventType;       // USER_REGISTERED, USER_LOGIN, USER_LOCKED, etc.
    private UUID userId;
    private String email;
    private String username;
    private Instant timestamp;
    private Map<String, String> metadata;  // extra data (IP, roles, etc.)
}

