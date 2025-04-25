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
import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.createClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultOAuthTokenRetriever implements TokenRetriever {
  private static final Logger LOGGER =
          LoggerFactory.getLogger(VaultOAuthTokenRetriever.class);

  private static final String VAULT_ENDPOINT_OPTION = "vaultUrl";
  private static final String VAULT_ROLE_PATH_OPTION = "vaultRolePath";
  private static final String VAULT_AUTH_ROLE_OPTION = "vaultAuthRole";
  private static final String KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH =
          "/var/run/secrets/kubernetes.io/serviceaccount/token";
  private static final String KUBERNETES_SERVICE_ACCOUNT_TOKEN_KEY =
          "KUBERNETES_SERVICE_ACCOUNT_TOKEN";

  private Client client;
  private WebTarget vaultWebTarget;
  private String vaultRolePath;
  private String vaultAuthRole;

  public VaultOAuthTokenRetriever() {
  }

  @Override
  public void configure(Map<String, String> options) {
    client = createClient(LOGGER);
    String vaultUrl = options.get(VAULT_ENDPOINT_OPTION);
    vaultWebTarget = client.target(vaultUrl);
    vaultRolePath = options.get(VAULT_ROLE_PATH_OPTION);
    vaultAuthRole = options.get(VAULT_AUTH_ROLE_OPTION);
  }

  public boolean isConfigured() {
    return (vaultRolePath != null) && (vaultAuthRole != null);
  }

  @Override
  public String retrieveAccessToken() {
    String vaultToken = login();

    WebTarget oidcWebTarget = vaultWebTarget.path("v1/identity/oidc/token/{oidc_role_path}")
            .resolveTemplate("oidc_role_path", vaultRolePath);
    Invocation.Builder invocationBuilder = oidcWebTarget.request(MediaType.APPLICATION_JSON_TYPE);
    invocationBuilder.header("X-Vault-Token", vaultToken);
    Map<String, Map<String, String>> response = invocationBuilder.get(Map.class);
    return response.get("data").get("token");
  }

  private String login() {
    WebTarget loginWebTarget = vaultWebTarget.path("v1/auth/kubernetes/login");
    Invocation.Builder invocationBuilder = loginWebTarget.request(MediaType.APPLICATION_JSON_TYPE);
    String jwt = getServiceAccountJwt();

    Map<String, String> loginBody = new HashMap<String, String>() {
      {
        put("jwt", jwt);
        put("role", vaultAuthRole);
      }
    };
    Map<String, Map<String, Object>> response =
            invocationBuilder.post(Entity.json(loginBody), Map.class);
    return (String) response.get("auth").get("client_token");
  }

  private String getServiceAccountJwt() {
    String jwt = System.getenv(KUBERNETES_SERVICE_ACCOUNT_TOKEN_KEY);
    if (jwt == null || jwt.isEmpty()) {
      try {
        jwt = new String(Files.readAllBytes(Paths.get(KUBERNETES_SERVICE_ACCOUNT_TOKEN_PATH)));
      } catch (IOException e) {
        LOGGER.error("Can not read service account token from inner Pod file", e);
      }
    }
    requireNonNull(jwt, "Can not get kubernetes service account jwt token");
    return jwt;
  }

  public String getIdpEndpoint() {
    return vaultWebTarget.getUri().toString();
  }

  @Override
  public void close() {
    if (client != null) {
      client.close();
    }
  }
}
