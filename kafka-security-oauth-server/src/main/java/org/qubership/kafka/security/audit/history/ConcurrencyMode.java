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
