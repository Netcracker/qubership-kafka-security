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
    ClientBuilder clientBuilder = ClientBuilder.newBuilder();
    try {
      clientBuilder.sslContext(SSLContext.getDefault());
    } catch (NoSuchAlgorithmException e) {
      logger.error("Cannot load default SSL context", e);
    }
    return clientBuilder.build();
  }
}
