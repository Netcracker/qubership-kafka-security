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

package org.qubership.kafka.security.audit;

import org.qubership.kafka.security.audit.history.CEFHistoryRecord;
import org.qubership.kafka.security.audit.history.CEFLog4jHistoryWriter;
import java.util.Map;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Facade for audit logic over kafka security.
 */
public class AuditRecordWriter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuditRecordWriter.class);

  private static final AuditRecordWriter INSTANCE = new AuditRecordWriter();
  private static final String AUDIT_LOGS_ENABLED = "auditLogsEnabled";
  private static final String AUDIT_LOGS_ENABLED_DEFAULT_VALUE = "false";
  private static final String AUDIT_CEF_CONFIG_PATH = "auditCefConfigPath";
  private static final String AUDIT_CEF_CONFIG_PATH_DEFAULT =
      "/opt/kafka/config/cef-configuration.xml";

  private CEFLog4jHistoryWriter cefLog4jAuditWriter;
  private boolean isAuditEnabled;
  private boolean isConfigured;

  /**
   * Returns instance of {@link AuditRecordWriter}. Instance should be configured with {@link
   * AuditRecordWriter#configure(Map)}.
   *
   * @return AuditRecordWriter instance
   */
  public static AuditRecordWriter getInstance() {
    return INSTANCE;
  }

  /**
   * Configures audit record writer.
   *
   * @param options kafka security options
   */
  public void configure(@Nonnull Map<String, String> options) {
    isAuditEnabled = Boolean.parseBoolean(options.getOrDefault(AUDIT_LOGS_ENABLED,
        AUDIT_LOGS_ENABLED_DEFAULT_VALUE));
    final String cefConfigFilePath = options.getOrDefault(AUDIT_CEF_CONFIG_PATH,
        AUDIT_CEF_CONFIG_PATH_DEFAULT);
    this.cefLog4jAuditWriter = isAuditEnabled
        ? new CEFLog4jHistoryWriter(new CEFSettingsFromXML(cefConfigFilePath)) : null;
    isConfigured = true;
    LOGGER.info("Audit Logging is {}", isAuditEnabled ? "enabled" : "disabled");
  }

  /**
   * Track in sync mode audit event.
   *
   * @param auditRecord audit record.
   */
  public void trackAuditEvent(CEFHistoryRecord auditRecord) {
    if (!isConfigured) {
      LOGGER.warn("Can't track audit log because AuditRecordWriter is not configured yet");
      return;
    }
    if (isAuditEnabled) {
      cefLog4jAuditWriter.write(auditRecord);
    }
  }
}
