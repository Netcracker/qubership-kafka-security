package org.qubership.kafka.security.audit;

import org.qubership.kafka.security.audit.history.CEFConfiguration;
import org.qubership.kafka.security.audit.history.SeverityNode;
import org.qubership.kafka.security.audit.history.CEFSettings;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

public class CEFSettingsFromXML implements CEFSettings {

  private static final String DEFAULT_CEF_CONFIGURATION_PATH =
      "/config/cef/cef-configuration-default.xml";

  private final CEFConfiguration cefConfiguration;
  private final Map<String, Integer> severityMap;

  CEFSettingsFromXML(final String cefConfigFilePath) {
    cefConfiguration = loadConfiguration(cefConfigFilePath);
    severityMap = loadSeverityMap(cefConfiguration);
  }

  @Override
  public int getCEFVersion() {
    return cefConfiguration.getCEFVersion();
  }

  @Override
  public String getDeviceVendor() {
    return cefConfiguration.getDeviceVendor();
  }

  @Override
  public String getDeviceProduct() {
    return cefConfiguration.getDeviceProduct();
  }

  @Override
  public String getDeviceVersion() {
    return cefConfiguration.getDeviceVersion();
  }

  @Override
  public Map<String, Integer> getSeverityMap() {
    return severityMap;
  }

  private CEFConfiguration loadConfiguration(final String cefConfigFilePath) {
    try {
      File cefConfigFile = new File(cefConfigFilePath);
      InputStream configurationSource = cefConfigFile.exists()
          ? new FileInputStream(cefConfigFile)
          : getClass().getResourceAsStream(DEFAULT_CEF_CONFIGURATION_PATH);

      Unmarshaller unmarshaller = JAXBContext.newInstance(CEFConfiguration.class)
          .createUnmarshaller();
      return (CEFConfiguration) unmarshaller.unmarshal(configurationSource);
    } catch (JAXBException | FileNotFoundException e) {
      throw new RuntimeException("Cannot load CEF Configuration from XML", e);
    }
  }

  private Map<String, Integer> loadSeverityMap(CEFConfiguration cefConfiguration) {
    List<SeverityNode> severityNodes = cefConfiguration.getSeverityMap().getSeverityNode();
    Map<String, Integer> severityMap = new HashMap<>(severityNodes.size(), 1);
    for (SeverityNode severityNode : severityNodes) {
      severityMap.put(severityNode.getEventSignature(), severityNode.getSeverity());
    }
    return severityMap;
  }
}
