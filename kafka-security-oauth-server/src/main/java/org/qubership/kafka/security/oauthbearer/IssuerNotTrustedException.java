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

import javax.annotation.Nonnull;

/**
 * Exception for case when issuer from JWT token is not trusted for application and cannot be
 * resolved by whitelist and rules.
 */
final class IssuerNotTrustedException extends Exception {

  private static final String ISSUER_IS_NOT_TRUSTED_MSG = "Issuer url '%s' is not found in "
      + "whitelist of Identity Provider and cannot be used";

  @Nonnull
  private final String issuer;

  /**
   * Default constructor for exception.
   *
   * @param issuer untrusted issuer url
   */
  IssuerNotTrustedException(@Nonnull String issuer) {
    super(String.format(ISSUER_IS_NOT_TRUSTED_MSG, issuer));
    this.issuer = issuer;
  }

  /**
   * Returns untrusted issuer.
   *
   * @return issuer url
   */
  @Nonnull
  String issuer() {
    return issuer;
  }
}
