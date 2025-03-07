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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.minidev.json.JSONObject;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple JWT implementation.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>
 */
public final class OAuthBearerJwt implements OAuthBearerToken {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuthBearerJwt.class);
  public static final String POINT = ".";
  public static final String SPACE = " ";
  public static final String SLASH = "/";

  private static final ObjectMapper OM = new ObjectMapper();

  @Nonnull
  private final String value;
  @Nonnull
  private final Set<String> scope;
  private final long lifetimeMs;
  @Nonnull
  private final String principalName;
  @Nullable
  private final Long startTimeMs;
  @Nonnull
  private final JWSHeader header;
  @Nonnull
  private final JSONObject payload;
  @Nonnull
  private final Set<String> roles;

  public OAuthBearerJwt(@Nonnull String token) {
    this(token, "");
  }

  OAuthBearerJwt(@Nonnull String token, @Nonnull String tokenRolesPath) {
    value = requireNonNull(token);
    final JWSObject jwsToken;
    try {
      jwsToken = JWSObject.parse(value);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Token does not have JWT-token structure", e);
    }
    header = jwsToken.getHeader();
    Map<String, Object> initialPayload = jwsToken.getPayload().toJSONObject();
    if (initialPayload == null) {
      throw new IllegalArgumentException("JWT Token does not have payload.");
    }
    payload = new JSONObject(initialPayload);
    Object scope = payload.get("scope");
    if (scope instanceof List) {
      Set<String> scopes = new HashSet<>();
      for (Object item : (List) scope) {
        scopes.add((String) item);
      }
      this.scope = Collections.unmodifiableSet(scopes);
    } else {
      this.scope = (scope == null) ? Collections.emptySet() : Collections.singleton((String) scope);
    }
    roles = calculateRoles(tokenRolesPath);
    lifetimeMs = Instant.ofEpochSecond(payload.getAsNumber("exp").longValue()).toEpochMilli();
    principalName = payload.getAsString("sub");
    Number startTimeMs = payload.getAsNumber("iat");
    this.startTimeMs = (startTimeMs == null)
        ? null : Instant.ofEpochSecond(startTimeMs.longValue()).toEpochMilli();
  }

  @Override
  public String value() {
    return value;
  }

  @Override
  public Set<String> scope() {
    return scope;
  }

  @Override
  public long lifetimeMs() {
    return lifetimeMs;
  }

  @Override
  public String principalName() {
    return principalName;
  }

  @Override
  public Long startTimeMs() {
    return startTimeMs;
  }

  /**
   * Returns the list of roles for current principal.
   *
   * @return set of roles
   */
  public Set<String> roles() {
    return roles;
  }

  /**
   * Returns encryption algorithm for token.
   *
   * @return encryption algorithm
   */
  @Nonnull
  JWSAlgorithm algorithm() {
    return header.getAlgorithm();
  }

  /**
   * Returns who created and signed the token.
   *
   * @return issuer url
   */
  @Nonnull
  String issuer() {
    return payload.getAsString("iss");
  }

  private Set<String> calculateRoles(String tokenRolesPath) {
    JsonNode roles = getNodeByPath(tokenRolesPath);
    if (roles instanceof ArrayNode) {
      Set<String> elements = new HashSet<>();
      for (int i = 0; i < roles.size(); ++i) {
        elements.add(roles.get(i).textValue());
      }
      return Collections.unmodifiableSet(elements);
    } else if (roles instanceof TextNode) {
      String[] rolesAsArray = roles.textValue().split(SPACE);
      Set<String> elements = new HashSet<>(Arrays.asList(rolesAsArray));
      return Collections.unmodifiableSet(elements);
    } else {
      return Collections.emptySet();
    }
  }

  private JsonNode getNodeByPath(String path) {
    try {
      JsonNode node = OM.readTree(payload.toJSONString());
      return node.at(SLASH + path.replace(POINT, SLASH));
    } catch (IOException e) {
      LOGGER.error("Cannot read tree from JSON", e);
      return null;
    }
  }
}
