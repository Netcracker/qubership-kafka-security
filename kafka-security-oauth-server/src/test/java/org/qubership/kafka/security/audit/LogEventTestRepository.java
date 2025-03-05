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