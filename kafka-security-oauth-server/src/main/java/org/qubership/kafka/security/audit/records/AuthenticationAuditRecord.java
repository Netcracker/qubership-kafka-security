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

package org.qubership.kafka.security.audit.records;

import java.util.Map;
import javax.annotation.Nonnull;

public class AuthenticationAuditRecord extends AbstractAuditRecord {

  private static final String AUTHENTICATION_EVENT_TYPE = "AUTHENTICATION_EVENT";
  private static final String AUTHENTICATION_FAILED_TYPE = "AUTHENTICATION_FAILED";

  @Nonnull
  private final String authenticationType;
  private final String reason;

  private AuthenticationAuditRecord(
      String principalName,
      String clientIp,
      @Nonnull String authenticationType,
      boolean result,
      String reason) {

    super(principalName, clientIp, result);
    this.authenticationType = authenticationType;
    this.reason = reason;
  }

  /**
   * Creates {@link AuthenticationAuditRecord} for successful authentication event.
   *
   * @param principalName name of principal
   * @param authenticationType type of authentication
   * @param clientIp client IP
   * @return audit record for successful login attempt
   */
  public static AuthenticationAuditRecord successful(@Nonnull String principalName,
      @Nonnull String authenticationType,
      String clientIp) {
    return new AuthenticationAuditRecord(principalName, clientIp, authenticationType,
        true,
        null);
  }

  /**
   * Creates {@link AuthenticationAuditRecord} for failed authentication event.
   *
   * @param principalName name of principal
   * @param authenticationType type of authentication
   * @param reason reason of failed authentication
   * @param clientIp client IP
   * @return audit record for failed login attempt
   */
  public static AuthenticationAuditRecord failed(String principalName,
      @Nonnull String authenticationType,
      @Nonnull String reason,
      String clientIp) {
    return new AuthenticationAuditRecord(principalName, clientIp, authenticationType,
        false,
        reason);
  }

  @Override
  public String getName() {
    return result
        ? String.format("Successful authentication for principal '%s' with client IP '%s'",
        principalName, clientIp)
        : String.format("Failed authentication for principal '%s' with client IP '%s': %s",
            principalName, clientIp, reason);
  }

  @Override
  public String getOperationType() {
    return result ? AUTHENTICATION_EVENT_TYPE : AUTHENTICATION_FAILED_TYPE;
  }

  @Override
  protected void enrichExtension(Map<String, String> extension) {
    extension.put("authenticationType", authenticationType);
  }
}
