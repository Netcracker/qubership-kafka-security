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
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

public class AuthorizationAuditRecord extends AbstractAuditRecord {

  private static final String AUTHORIZATION_EVENT_TYPE = "AUTHORIZATION_EVENT";
  private static final String AUTHORIZATION_FAILED_TYPE = "AUTHORIZATION_FAILED";
  private static final String AUTHORIZED_RESULT = "authorized";
  private static final String UNAUTHORIZED_RESULT = "unauthorized";

  private final KafkaPrincipal kafkaPrincipal;
  private final AclOperation operation;
  private final ResourcePattern resource;

  /**
   * Create new instance.
   */
  public AuthorizationAuditRecord(
      @Nonnull KafkaPrincipal principal,
      @Nonnull String clientIp,
      @Nonnull AclOperation operation,
      @Nonnull ResourcePattern resource,
      boolean result) {
    super(principal.getName(), clientIp, result);
    this.kafkaPrincipal = principal;
    this.operation = operation;
    this.resource = resource;
  }

  @Override
  protected void enrichExtension(Map<String, String> extension) {
    extension.put("operation", operation.name());
    extension.put("resource", resource.toString());
  }

  @Override
  public String getName() {
    return String.format("Principal '%s' "
            + "with client IP '%s' is %s to perform operation '%s' on resource '%s'",
        kafkaPrincipal,
        clientIp,
        result ? AUTHORIZED_RESULT : UNAUTHORIZED_RESULT,
        operation,
        resource);
  }

  @Override
  public String getOperationType() {
    return result ? AUTHORIZATION_EVENT_TYPE : AUTHORIZATION_FAILED_TYPE;
  }

}
