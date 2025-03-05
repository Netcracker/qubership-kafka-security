package org.qubership.kafka.security.audit.history;

/**
 * Flushes given records to any kind of history storage, which depends solely on
 * implementation.
 *
 * @param <T> type of the history record, which must be accepted by this writer.
 */
public interface HistoryWriter<T extends HistoryRecord> {

  /**
   * Returns true, if this writer is enabled, otherwise false.
   * If the writer is disabled, it does not track anything.
   *
   * @return true, if this writer is enabled, otherwise false.
   */
  boolean isEnabled();

  /**
   * Writes given record to the history storage.
   *
   * @param historyRecord record to be stored.
   */
  void write(T historyRecord);
}
