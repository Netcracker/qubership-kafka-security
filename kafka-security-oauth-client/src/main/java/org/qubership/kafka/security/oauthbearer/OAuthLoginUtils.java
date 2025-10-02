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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.annotation.Nonnull;
import javax.net.ssl.SSLContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.slf4j.Logger;

public class OAuthLoginUtils {

  public static String clientCredentials(String clientId, String clientSecret) {
    String credentials = clientId + ":" + clientSecret;
    return new String(Base64.getEncoder().encode(credentials.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Normalizes given url.
   * <p>For example: {@code http://identity-provider:8080//token} is normalized to
   * {@code http://identity-provider:8080/token}</p>
   *
   * @param url url to normalize
   * @return normalized url
   * @throws URISyntaxException if the given string violates RFC 2396
   */
  @Nonnull
  static String normalizeUrl(@Nonnull String url) throws URISyntaxException {
    return new URI(url).normalize().toString();
  }

  static Client createClient(Logger logger) {
    ClassLoader prev = Thread.currentThread().getContextClassLoader();
    try {
      Thread.currentThread().setContextClassLoader(ClientBuilder.class.getClassLoader());
      ClientBuilder builder = ClientBuilder.newBuilder();
      return builder.build();
    } finally {
      Thread.currentThread().setContextClassLoader(prev);
    }
  }
}
