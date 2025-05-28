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

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import org.qubership.kafka.security.audit.records.AuthenticationAuditRecord;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Filter.Result;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.filter.LevelRangeFilter;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AuditRecordWriterTest {

  private static LogEventTestRepository logEventTestRepository;

  @BeforeClass
  public static void beforeClass() {
    initTestLogAppender();
  }

  private static void initTestLogAppender() {
    logEventTestRepository = new LogEventTestRepository("testAuditAppender", null, null);

    LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);

    Configuration configuration = loggerContext.getConfiguration();
    LoggerConfig rootLoggerConfig = configuration.getLoggerConfig("");

    rootLoggerConfig.addAppender(
        logEventTestRepository, org.apache.logging.log4j.Level.INFO,
        LevelRangeFilter.createFilter(
            org.apache.logging.log4j.Level.INFO, org.apache.logging.log4j.Level.INFO,
            Result.ACCEPT, Result.NEUTRAL
        )
    );
  }

  @After
  public void after() {
    logEventTestRepository.clearLogEvents();
  }

  @Before
  public void before() {
    logEventTestRepository.clearLogEvents();
  }

  @Test
  public void testAuthenticationEventWithDisabledLogs() {
    Map<String, String> options = Collections.singletonMap("auditLogsEnabled", "false");
    AuditRecordWriter.getInstance().configure(options);

    AuditRecordWriter.getInstance().trackAuditEvent(
        AuthenticationAuditRecord.successful(
            "admin",
            "SASL",
            "1.1.1.1")
    );

    List<String> logEvents = logEventTestRepository.getLogEvents();
    assertTrue("Audit log should be empty", logEvents.isEmpty());
  }

  @Test
  public void testSuccessfulAuthenticationEvent() {
    String expectedLogValue = "CEF:1|qubership|Kafka|3.9.1|AUTHENTICATION_EVENT|Successful authentication for principal 'admin' with client IP '1.1.1.1'|2|result=successful suser=admin src=1.1.1.1 authenticationType=SASL type=audit_log_type";

    Map<String, String> options = Collections.singletonMap("auditLogsEnabled", "true");
    AuditRecordWriter.getInstance().configure(options);

    AuditRecordWriter.getInstance().trackAuditEvent(
        AuthenticationAuditRecord.successful(
            "admin",
            "SASL",
            "1.1.1.1")
    );

    List<String> logEvents = logEventTestRepository.getLogEvents();
    assertFalse("Audit log is empty", logEvents.isEmpty());
    String auditLogMessage = logEvents.get(0);

    assertThat("Invalid audit log message", auditLogMessage, equalTo(expectedLogValue));
  }

  @Test
  public void testFailedAuthenticationEvent() {
    String expectedLogValue = "CEF:1|qubership|Kafka|3.9.1|AUTHENTICATION_FAILED|Failed authentication for principal 'admin' with client IP '1.1.1.1': Incorrect password|6|result=failed suser=admin src=1.1.1.1 authenticationType=SASL type=audit_log_type";

    Map<String, String> options = Collections.singletonMap("auditLogsEnabled", "true");
    AuditRecordWriter.getInstance().configure(options);

    AuditRecordWriter.getInstance().trackAuditEvent(
        AuthenticationAuditRecord.failed(
            "admin",
            "SASL",
            "Incorrect password",
            "1.1.1.1")
    );

    List<String> logEvents = logEventTestRepository.getLogEvents();
    assertFalse("Audit log is empty", logEvents.isEmpty());
    String auditLogMessage = logEvents.get(0);

    assertThat("Invalid audit log message", auditLogMessage, equalTo(expectedLogValue));
  }

}
