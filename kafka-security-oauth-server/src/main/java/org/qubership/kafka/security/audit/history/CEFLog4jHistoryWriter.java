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

import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class performs logging of messages in CEF (Common Event Format) that is used for integration
 * with SIEM systems.
 */
@Writer(concurrencyMode = ConcurrencyMode.ASYNC_ORDERED, trackChildRecords = true)
public class CEFLog4jHistoryWriter implements HistoryWriter<CEFHistoryRecord> {

  private static final int DEFAULT_SEVERITY = 5;

  private static final ConcurrentHashMap<String, Logger> loggers = new ConcurrentHashMap<>();

  private final CEFSettings cefSettings;
  /**
   * CEF is the following:<br> CEF:Version|Device Vendor|Device Product|Device Version|Signature
   * ID|Name|Severity|Extension
   *
   * <p>Version, Device Vendor, Device Product and Device Version are
   * configured globally and provided in constructor. Other fields contain event information. So
   * the template is the following: <br> CEF:Version|Device Vendor|Device Product|Device
   * Version|%s|%s|%d|%s
   */
  private final String cefMessageTemplate;

  public CEFLog4jHistoryWriter(final CEFSettings cefSettings) {
    this.cefSettings = cefSettings;
    cefMessageTemplate = new StringBuilder("CEF:").append(cefSettings.getCEFVersion()).append('|')
        .append(escapeSymbols(cefSettings.getDeviceVendor(), true)).append('|')
        .append(escapeSymbols(cefSettings.getDeviceProduct(), true)).append('|')
        .append(escapeSymbols(cefSettings.getDeviceVersion(), true)).append("|%s|%s|%d|%s")
        .toString();
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public void write(CEFHistoryRecord historyRecord) {
    String category = historyRecord.getCategory();
    Logger logger = loggers.get(category);
    if (logger == null) {
      logger = LoggerFactory.getLogger(category);
      loggers.put(category, logger);
    }
    if (logger.isInfoEnabled()) {
      logger.info(
          String.format(cefMessageTemplate, escapeSymbols(historyRecord.getOperationType(), true),
              escapeSymbols(historyRecord.getName(), true),
              MoreObjects.firstNonNull(cefSettings.getSeverityMap()
                  .get(historyRecord.getOperationType()), DEFAULT_SEVERITY),
              generateExtensionField(historyRecord.getExtension())));

    }
  }

  /**
   * Generates extension part for CEF message.
   *
   * @param extension map with key-value pairs containing additional information about event
   * @return extension part of the message
   */
  private String generateExtensionField(Map<String, String> extension) {
    StringBuilder extensionFieldBuilder = new StringBuilder();
    Iterator<Map.Entry<String, String>> extensionEntriesIterator = extension.entrySet().iterator();
    while (extensionEntriesIterator.hasNext()) {
      Map.Entry<String, String> extensionEntry = extensionEntriesIterator.next();
      String extensionKey = extensionEntry.getKey();
      String extensionValue = Strings.nullToEmpty(extensionEntry.getValue());
      if (extensionKey.contains(" ")) {
        throw new IllegalArgumentException("Space symbol found in key=\"" + extensionKey
            + "\". Space symbols aren't allowed in extension keys.");
      }
      extensionFieldBuilder.append(escapeSymbols(extensionKey, false)).append('=')
          .append(escapeSymbols(extensionValue, false));
      if (extensionEntriesIterator.hasNext()) {
        extensionFieldBuilder.append(' ');
      }
    }
    return extensionFieldBuilder.toString();
  }

  /**
   * Performs escaping of values that is used in CEF message. It is based on following rules: <ul>
   * <li>If a pipe (|) is used in the prefix, it has to be escaped with a backslash (\). But note
   * that pipes in the extension do not need escaping.</li> <li>If a backslash (\) is used in the
   * prefix or the extension, it has to be escaped with another backslash (\).</li> <li>If an
   * equal sign (=) is used in the extensions, it has to be escaped with a backslash (\). Equal
   * signs in the prefix need no escaping.</li> <li>Multi-line fields can be sent by CEF by
   * encoding the newline character as \n or \r. Note that multiple lines are only allowed in the
   * value part of the extensions.</li> </ul>
   *
   * @param value input string
   * @param isPrefixPart describes whether value that needs to be escaped is part of the prefix or
   *     part of the extension of the message
   * @return escaped value
   */
  private String escapeSymbols(final String value, final boolean isPrefixPart) {
    StringBuilder buffer = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char currentSymbol = value.charAt(i);
      switch (currentSymbol) {
        case ('|'):
          if (isPrefixPart) {
            buffer.append("\\|");
          } else {
            buffer.append(currentSymbol);
          }
          break;
        case ('\\'):
          buffer.append("\\\\");
          break;
        case ('='):
          if (isPrefixPart) {
            buffer.append(currentSymbol);
          } else {
            buffer.append("\\=");
          }
          break;
        case ('\n'):
          if (!isPrefixPart) {
            buffer.append("\\n");
          }
          break;
        case ('\r'):
          if (!isPrefixPart) {
            buffer.append("\\r");
          }
          break;
        default:
          buffer.append(currentSymbol);
      }
    }
    return buffer.toString();
  }
}
