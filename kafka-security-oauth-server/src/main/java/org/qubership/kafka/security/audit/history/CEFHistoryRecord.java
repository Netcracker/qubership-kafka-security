package org.qubership.kafka.security.audit.history;

import java.util.Map;
import java.util.Date;

public interface CEFHistoryRecord extends HistoryRecord {

  /**
   * @return human-readable and understandable description of the event.
   */
  public String getName();

  /**
   * @return collection of key-value pairs containing additional information about the event.
   */
  public Map<String, String> getExtension();

  /**
   * @return logging category of the event.
   */
  public String getCategory();
}
