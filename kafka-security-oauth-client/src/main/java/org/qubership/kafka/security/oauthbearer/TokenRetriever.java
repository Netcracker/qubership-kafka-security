package org.qubership.kafka.security.oauthbearer;

import java.util.Map;

public interface TokenRetriever {
  void configure(Map<String, String> options);

  boolean isConfigured();

  String retrieveAccessToken();

  String getIdpEndpoint();

  void close();
}
