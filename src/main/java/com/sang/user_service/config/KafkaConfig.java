package com.sang.user_service.config;

import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.kafka.autoconfigure.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Kafka Configuration - uses Jackson 3.x ObjectMapper (tools.jackson)
 * to serialize Kafka messages with proper support for Instant, UUID, etc.
 */
@Configuration
public class KafkaConfig {

    @Bean
    public ProducerFactory<String, Object> producerFactory(KafkaProperties kafkaProperties) {
        var props = kafkaProperties.buildProducerProperties();
        var factory = new DefaultKafkaProducerFactory<String, Object>(props);

        // Jackson 3.x ObjectMapper with Java time support built-in
        ObjectMapper mapper = JsonMapper.builder().build();

        Serializer<Object> valueSerializer = new Serializer<>() {
            @Override
            public byte[] serialize(String topic, Object data) {
                if (data == null) return null;
                try {
                    return mapper.writeValueAsBytes(data);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to serialize Kafka message", e);
                }
            }
        };

        factory.setValueSerializer(valueSerializer);
        factory.setKeySerializer(new StringSerializer());
        return factory;
    }

    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> producerFactory) {
        return new KafkaTemplate<>(producerFactory);
    }
}
