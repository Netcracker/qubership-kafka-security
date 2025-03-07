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

import org.qubership.kafka.security.audit.AuditConstants;
import org.qubership.kafka.security.audit.history.CEFHistoryRecord;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract audit record for Kafka security operations.
 */
public abstract class AbstractAuditRecord implements CEFHistoryRecord {

  private static final String USERNAME_EXTENSION_TAG = "suser";
  private static final String CLIENT_IP_EXTENSION_TAG = "src";
  private static final String TYPE_EXTENSION_TAG = "type";
  private static final String AUDIT_TYPE_EXTENSION_VALUE = "audit_log_type";
  private static final String RESULT_EXTENSION_TAG = "result";
  protected final String principalName;
  protected final String clientIp;
  protected final boolean result;
  private final Date recordDate;

  /**
   * Default constructor.
   *
   * @param principalName name of principal
   * @param clientIp client IP
   * @param result event result (true if successful)
   */
  public AbstractAuditRecord(String principalName, String clientIp, boolean result) {
    this.principalName = principalName;
    this.clientIp = clientIp;
    this.result = result;
    this.recordDate = new Date();
  }

  @Override
  public Date getTimestamp() {
    return recordDate;
  }

  @Override
  public String getCategory() {
    return AuditConstants.KAFKA_AUDIT_CATEGORY;
  }

  @Override
  public Map<String, String> getExtension() {
    Map<String, String> extensionMap = new HashMap<>();
    if (principalName != null) {
      extensionMap.put(USERNAME_EXTENSION_TAG, principalName);
    }
    if (clientIp != null) {
      extensionMap.put(CLIENT_IP_EXTENSION_TAG, clientIp);
    }
    extensionMap.put(RESULT_EXTENSION_TAG, result ? "successful" : "failed");
    enrichExtension(extensionMap);
    extensionMap.put(TYPE_EXTENSION_TAG, AUDIT_TYPE_EXTENSION_VALUE);
    return extensionMap;
  }

  /**
   * Enriches extension map with extension for specific audit record.
   *
   * @param extension extension map
   */
  protected abstract void enrichExtension(Map<String, String> extension);
}
