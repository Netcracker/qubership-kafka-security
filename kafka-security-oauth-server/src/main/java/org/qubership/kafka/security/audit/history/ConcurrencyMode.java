package org.qubership.kafka.security.audit.history;

/**
 * Threading model for writers call. Determines, how many threads are to be used, and in which
 * manner (synchronously/asynchronously).
 */
public enum ConcurrencyMode {

  /**
   * In this mode writer can write asynchronously in many threads. Number of threads
   * is defined by the property <b>history.engine.async.queuesPerWriter</b>.
   */
  ASYNC,

  /**
   * In this mode writer can write asynchronously, but only in one thread. Should be used, if order
   * of records should be preserved, but separate thread for tracking task is still preferred.
   */
  ASYNC_ORDERED,

  /**
   * In this mode writer will write only synchronously, i.e. in the thread, from which it was
   * called.
   */
  SYNC
}
