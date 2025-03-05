package org.qubership.kafka.security.audit.history;

import java.util.Map;

public interface CEFSettings {

  public int getCEFVersion();

  public String getDeviceVendor();

  public String getDeviceProduct();

  public String getDeviceVersion();

  public Map<String, Integer> getSeverityMap();
}
