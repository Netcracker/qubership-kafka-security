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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

/**
 * This class is appender and repository for in-memory storing of log events
 */
public class LogEventTestRepository extends AbstractAppender {

  private final static List<String> logEvents = new ArrayList<>();

  public LogEventTestRepository(
      String name, Filter filter,
      Layout<? extends Serializable> layout
  ) {
    super(name, filter, layout, true, Property.EMPTY_ARRAY);
  }

  public void clearLogEvents() {
    logEvents.clear();
  }

  public List<String> getLogEvents() {
    return logEvents;
  }

  /**
   * Track audit log messages from kafka.audit topic
   */
  @Override
  public void append(LogEvent logEvent) {
    if (AuditConstants.KAFKA_AUDIT_CATEGORY.equals(logEvent.getLoggerName())) {
      logEvents.add(logEvent.getMessage().toString());
    }
  }
}