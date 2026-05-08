package com.sang.user_service.event;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * Kafka Event Producer - publishes user events to Kafka topics.
 *
 * Topics:
 *   user-events → consumed by notification-service, account-service, etc.
 *
 * HOW IT WORKS:
 *   1. AuthService calls publishEvent() after register/login/lock
 *   2. KafkaTemplate serializes UserEvent to JSON and sends to Kafka
 *   3. notification-service listens on "user-events" topic and processes
 */
@Service
@RequiredArgsConstructor
public class UserEventProducer {

    private static final Logger logger = LoggerFactory.getLogger(UserEventProducer.class);
    private static final String TOPIC = "user-events";

    private final KafkaTemplate<String, Object> kafkaTemplate;

    /**
     * Publish a user event to Kafka.
     * Uses userId as the message key → ensures events for same user go to same partition (ordering).
     */
    public void publishEvent(UserEvent event) {
        String key = event.getUserId() != null ? event.getUserId().toString() : event.getEmail();

        kafkaTemplate.send(TOPIC, key, event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        logger.error("Failed to publish event [{}] for user [{}]: {}",
                                event.getEventType(), event.getEmail(), ex.getMessage());
                    } else {
                        logger.info("Published event [{}] for user [{}] to topic [{}], partition [{}], offset [{}]",
                                event.getEventType(),
                                event.getEmail(),
                                result.getRecordMetadata().topic(),
                                result.getRecordMetadata().partition(),
                                result.getRecordMetadata().offset());
                    }
                });
    }
}

