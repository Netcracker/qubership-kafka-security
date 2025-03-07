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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation is used to mark a spring bean as a history writer.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Writer {

  /**
   * Determines, if this writer tracks only given class of records, or
   * its descendants too.
   *
   * @return true, if all subclasses of specified record type are tracked to this writer, otherwise
   * false.
   */
  boolean trackChildRecords() default false;

  /**
   * Determines threading and ordering strategy for this writer.
   *
   * @return threading and order mode.
   */
  ConcurrencyMode concurrencyMode() default ConcurrencyMode.ASYNC;
}
