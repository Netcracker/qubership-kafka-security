package org.qubership.kafka.security.audit.history;

import java.util.Date;

/**
 * History record is a container for properties of history event or audit event.
 */
public interface HistoryRecord {

  /**
   * @return {@link Date} value of generation history record.
   */
  Date getTimestamp();

  /**
   * @return unique name of history record type.
   */
  String getOperationType();
}