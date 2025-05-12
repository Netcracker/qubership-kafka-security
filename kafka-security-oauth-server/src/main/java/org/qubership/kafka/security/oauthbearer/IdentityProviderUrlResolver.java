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

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is designed to resolve url of Identity Provider by issuer value in accordance with
 * rules.
 */
@ThreadSafe
final class IdentityProviderUrlResolver {
  private static final Logger LOGGER =
          LoggerFactory.getLogger(IdentityProviderUrlResolver.class);

  private static final String INTERNAL_FIELD = "internal";
  private static final String EXTERNAL_FILED = "external";

  @Nonnull
  private final List<Address> whitelist;

  private IdentityProviderUrlResolver(@Nonnull List<Address> whitelist) {
    this.whitelist = whitelist;
  }

  @Nonnull
  static IdentityProviderUrlResolver create(@Nullable String whitelist) {
    return new IdentityProviderUrlResolver(transformWhitelist(whitelist));
  }

  private static List<Address> transformWhitelist(@Nullable String whitelist) {
    if (whitelist == null || whitelist.isEmpty()) {
      return Collections.emptyList();
    }
    List<Address> result = new ArrayList<>();
    JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
    final JSONArray jsonWhitelist;
    try {
      jsonWhitelist = (JSONArray) parser.parse(whitelist);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Whitelist is in non-JSON format", e);
    }
    for (Object item : jsonWhitelist) {
      JSONObject jsonAddress = (JSONObject) item;
      String internal = jsonAddress.getAsString(INTERNAL_FIELD);
      String external = jsonAddress.getAsString(EXTERNAL_FILED);
      result.add(new Address(internal, external));
    }
    return result;
  }

  /**
   * Resolves url of Identity Provider by issuer name in accordance with configured rules.
   *
   * @param url url of Identity Provider to resolve
   * @return trusted url
   * @throws IssuerNotTrustedException in case of url cannot be resolved by rules
   */
  String resolveUrl(@Nonnull String url) throws IssuerNotTrustedException {
    Address trusted = whitelist.stream()
        .filter(address -> url.equals(address.external()) || url.equals(address.internal()))
        .findFirst()
        .orElseThrow(() -> new IssuerNotTrustedException(url));
    return trusted.internal() != null ? trusted.internal() : trusted.external();
  }

  @ThreadSafe
  private static final class Address {

    @Nullable
    private final String internal;
    @Nonnull
    private final String external;

    private Address(@Nullable String internal, @Nonnull String external) {
      this.internal = internal;
      this.external = external;
    }

    @Nullable
    private String internal() {
      return internal;
    }

    @Nonnull
    private String external() {
      return external;
    }

    @Override
    public String toString() {
      return "Address{"
              + "internal='" + internal + '\''
              + ", external='" + external + '\''
              + '}';
    }
  }
}
