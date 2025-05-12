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

import static java.util.Objects.requireNonNull;
import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.clientCredentials;
import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.createClient;
import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.normalizeUrl;

import java.net.URISyntaxException;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthTokenRetriever implements TokenRetriever {
  private static final Logger LOGGER =
          LoggerFactory.getLogger(OAuthTokenRetriever.class);

  private static final String CLIENT_ID_OPTION = "clientId";
  private static final String CLIENT_SECRET_OPTION = "clientSecret";
  private static final String TOKEN_ENDPOINT_OPTION = "tokenEndpoint";

  private Client client;
  private String tokenEndpoint;
  private String clientId;
  private String clientSecret;

  public OAuthTokenRetriever() {
  }

  @Override
  public void configure(Map<String, String> options) {
    client = createClient(LOGGER);
    tokenEndpoint = getTokenEndpoint(options);
    clientId = options.get(CLIENT_ID_OPTION);
    clientSecret = options.get(CLIENT_SECRET_OPTION);
  }

  @Override
  public boolean isConfigured() {
    if (tokenEndpoint == null || clientId == null || clientSecret == null) {
      LOGGER.debug("This login cannot be used to establish client connections");
      return false;
    }
    return true;
  }

  @Nullable
  private String getTokenEndpoint(@Nonnull Map<String, String> options) {
    String tokenEndpoint = options.get(TOKEN_ENDPOINT_OPTION);
    if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
      return null;
    }
    try {
      return normalizeUrl(tokenEndpoint);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(
              String.format("Invalid token endpoint: %s", tokenEndpoint), e);
    }
  }

  @Override
  public String retrieveAccessToken() {
    WebTarget webTarget = client.target(tokenEndpoint);
    Form form = new Form();
    form.param("grant_type", "client_credentials");
    Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON_TYPE);
    invocationBuilder.header("Authorization", "Basic " + clientCredentials(clientId, clientSecret));
    Entity<?> entity = Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED);
    @SuppressWarnings("unchecked")
    Map<String, String> response = invocationBuilder.post(entity, Map.class);
    requireNonNull(response,
        () -> String.format(
                "Token endpoint cannot be obtained: invalid response from: %s", tokenEndpoint));
    String res = response.get("access_token");
    return res;
  }

  public String getIdpEndpoint() {
    return tokenEndpoint;
  }

  @Override
  public void close() {
    if (client != null) {
      client.close();
    }
  }
}
