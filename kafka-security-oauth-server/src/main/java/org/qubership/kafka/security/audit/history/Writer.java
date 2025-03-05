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
