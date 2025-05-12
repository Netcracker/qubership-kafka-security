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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Java class for anonymous complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="CEFVersion" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="DeviceVendor" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="DeviceProduct" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="DeviceVersion" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="SeverityMap" type="{}severityMap"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * </p>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "cefVersion",
    "deviceVendor",
    "deviceProduct",
    "deviceVersion",
    "severityMap"
})
@XmlRootElement(name = "CEFConfiguration")
public class CEFConfiguration {

  @XmlElement(name = "CEFVersion")
  protected int cefVersion;
  @XmlElement(name = "DeviceVendor", required = true)
  protected String deviceVendor;
  @XmlElement(name = "DeviceProduct", required = true)
  protected String deviceProduct;
  @XmlElement(name = "DeviceVersion", required = true)
  protected String deviceVersion;
  @XmlElement(name = "SeverityMap", required = true)
  protected SeverityMap severityMap;

  /**
   * Gets the value of the cefVersion property.
   */
  public int getCEFVersion() {
    return cefVersion;
  }

  /**
   * Sets the value of the cefVersion property.
   */
  public void setCEFVersion(int value) {
    this.cefVersion = value;
  }

  /**
   * Gets the value of the deviceVendor property.
   *
   * @return possible object is {@link String }
   */
  public String getDeviceVendor() {
    return deviceVendor;
  }

  /**
   * Sets the value of the deviceVendor property.
   *
   * @param value allowed object is {@link String }
   */
  public void setDeviceVendor(String value) {
    this.deviceVendor = value;
  }

  /**
   * Gets the value of the deviceProduct property.
   *
   * @return possible object is {@link String }
   */
  public String getDeviceProduct() {
    return deviceProduct;
  }

  /**
   * Sets the value of the deviceProduct property.
   *
   * @param value allowed object is {@link String }
   */
  public void setDeviceProduct(String value) {
    this.deviceProduct = value;
  }

  /**
   * Gets the value of the deviceVersion property.
   *
   * @return possible object is {@link String }
   */
  public String getDeviceVersion() {
    return deviceVersion;
  }

  /**
   * Sets the value of the deviceVersion property.
   *
   * @param value allowed object is {@link String }
   */
  public void setDeviceVersion(String value) {
    this.deviceVersion = value;
  }

  /**
   * Gets the value of the severityMap property.
   *
   * @return possible object is {@link SeverityMap }
   */
  public SeverityMap getSeverityMap() {
    return severityMap;
  }

  /**
   * Sets the value of the severityMap property.
   *
   * @param value allowed object is {@link SeverityMap }
   */
  public void setSeverityMap(SeverityMap value) {
    this.severityMap = value;
  }

}
