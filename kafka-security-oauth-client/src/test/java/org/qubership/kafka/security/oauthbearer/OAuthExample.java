/*
 * Copyright 2024-2025 NetCracker Technology Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.qubership.kafka.security.oauthbearer;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;

public class OAuthExample {

  private static final String STRING_SERIALIZER_CLASS = StringSerializer.class.getName();
  private static final String STRING_DESERIALIZER_CLASS = StringDeserializer.class.getName();
  private static final String GROUP_ID = "kafka-oauth-example-group";
  private static final String TOPIC = "kafka-oauth-example-topic";
  private static final String USERNAME = "client";
  private static final String PASSWORD = "client";
  private static final String SASL_SCRAM_JAAS_CONFIG =
      "org.apache.kafka.common.security.scram.ScramLoginModule required "
          + "username=\"" + USERNAME + "\" "
          + "password=\"" + PASSWORD + "\";";
  private static final String CLIENT_ID = "TBD";
  private static final String CLIENT_SECRET = "TBD";
  private static final String TOKEN_ENDPOINT = "http://localhost:8080/token";
  private static final String VAULT_URL = "http://localhost:8200";
  private static final String VAULT_ROLE_PATH = "TBD";
  private static final String VAULT_AUTH_ROLE = "TBD";
  private static final String SASL_OAUTHBEARER_JAAS_CONFIG =
      "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required "
          + "clientId=\"" + CLIENT_ID + "\" "
          + "clientSecret=\"" + CLIENT_SECRET + "\" "
          + "tokenEndpoint=\"" + TOKEN_ENDPOINT + "\";";
  private static final String SASL_VAULTOAUTH_JAAS_CONFIG =
      "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required "
          + "vaultUrl=\"" + VAULT_URL + "\" "
          + "vaultRolePath=\"" + VAULT_ROLE_PATH + "\" "
          + "vaultAuthRole=\"" + VAULT_AUTH_ROLE + "\";";

  private static void produce(SaslMechanism saslMechanism) throws Exception {
    Properties properties = new Properties();
    properties.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    properties.put(KEY_SERIALIZER_CLASS_CONFIG, STRING_SERIALIZER_CLASS);
    properties.put(VALUE_SERIALIZER_CLASS_CONFIG, STRING_SERIALIZER_CLASS);
    properties.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT");
    if (saslMechanism == SaslMechanism.SCRAM) {
      properties.put(SaslConfigs.SASL_MECHANISM, "SCRAM-SHA-512");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_SCRAM_JAAS_CONFIG);
    } else if (saslMechanism == SaslMechanism.OAUTHBEARER) {
      properties.put(SaslConfigs.SASL_MECHANISM, "OAUTHBEARER");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_OAUTHBEARER_JAAS_CONFIG);
      properties.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS,
          "org.qubership.kafka.security.oauthbearer.OAuthBearerLoginCallbackHandler");
    } else if (saslMechanism == SaslMechanism.VAULTOAUTH) {
      properties.put(SaslConfigs.SASL_MECHANISM, "OAUTHBEARER");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_VAULTOAUTH_JAAS_CONFIG);
      properties.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS,
              "org.qubership.kafka.security.oauthbearer.VaultOAuthBearerLoginCallbackHandler");
    }
    try (KafkaProducer<String, String> producer = new KafkaProducer<>(properties)) {
      System.out.println(saslMechanism + " producer start: " + new Date());
      send(producer, new ProducerRecord<>(TOPIC, "1", "test1"));
      System.out.println("1: " + new Date());
      Thread.sleep(1000L);
      send(producer, new ProducerRecord<>(TOPIC, "2", "test2"));
      System.out.println("2: " + new Date());
      Thread.sleep(1000L);
      send(producer, new ProducerRecord<>(TOPIC, "3", "test3"));
      System.out.println("3: " + new Date());
      Thread.sleep(1000L);
      send(producer, new ProducerRecord<>(TOPIC, "4", "test4"));
      System.out.println("4: " + new Date());
      Thread.sleep(1000L);
      send(producer, new ProducerRecord<>(TOPIC, "5", "test5"));
      System.out.println("5: " + new Date());
      Thread.sleep(1000L);
      send(producer, new ProducerRecord<>(TOPIC, "6", "test6"));
      System.out.println("6: " + new Date());
      Thread.sleep(1000L);
      System.out.println(saslMechanism + " producer end: " + new Date());
    }
  }

  private static void send(
      KafkaProducer<String, String> producer, ProducerRecord<String, String> record)
      throws InterruptedException, ExecutionException, TimeoutException {
    producer.send(record).get(1000L, TimeUnit.MILLISECONDS);
  }

  private static void consume(SaslMechanism saslMechanism) {
    Properties properties = new Properties();
    properties.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
    properties.put(ConsumerConfig.GROUP_ID_CONFIG, GROUP_ID);
    properties.put(KEY_DESERIALIZER_CLASS_CONFIG, STRING_DESERIALIZER_CLASS);
    properties.put(VALUE_DESERIALIZER_CLASS_CONFIG, STRING_DESERIALIZER_CLASS);

    properties.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT");
    if (saslMechanism == SaslMechanism.SCRAM) {
      properties.put(SaslConfigs.SASL_MECHANISM, "SCRAM-SHA-512");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_SCRAM_JAAS_CONFIG);
    } else if (saslMechanism == SaslMechanism.OAUTHBEARER) {
      properties.put(SaslConfigs.SASL_MECHANISM, "OAUTHBEARER");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_OAUTHBEARER_JAAS_CONFIG);
      properties.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS,
          "org.qubership.kafka.security.oauthbearer.OAuthBearerLoginCallbackHandler");
    } else if (saslMechanism == SaslMechanism.VAULTOAUTH) {
      properties.put(SaslConfigs.SASL_MECHANISM, "OAUTHBEARER");
      properties.put(SaslConfigs.SASL_JAAS_CONFIG, SASL_VAULTOAUTH_JAAS_CONFIG);
      properties.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS,
              "org.qubership.kafka.security.oauthbearer.VaultOAuthBearerLoginCallbackHandler");
    }
    try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(properties)) {
      System.out.println(saslMechanism + " consumer start: " + new Date());
      consumer.subscribe(Collections.singleton(TOPIC), new ConsumerRebalanceListener() {
        @Override
        public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
          consumer.seekToBeginning(partitions);
        }

        @Override
        public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
        }
      });
      ConsumerRecords<String, String> records = null;
      while (records == null || records.isEmpty()) {
        records = consumer.poll(Duration.ofMillis(1000L));
      }
      for (ConsumerRecord<String, String> record : records) {
        System.out.println("key: " + record.key() + ", value: " + record.value());
      }
      System.out.println(saslMechanism + " consumer end: " + new Date());
    }
  }

  /**
   * Main method.
   */
  public static void main(String[] args) throws Exception {
    produce(SaslMechanism.SCRAM);
    consume(SaslMechanism.SCRAM);
    produce(SaslMechanism.OAUTHBEARER);
    consume(SaslMechanism.OAUTHBEARER);
//    produce(SaslMechanism.VAULTOAUTH);
//    consume(SaslMechanism.VAULTOAUTH);
  }

  private enum SaslMechanism {
    SCRAM,
    OAUTHBEARER,
    VAULTOAUTH
  }
}
