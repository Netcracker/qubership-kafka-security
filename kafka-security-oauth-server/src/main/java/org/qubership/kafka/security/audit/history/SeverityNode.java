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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * Java class for severityNode complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="severityNode">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="eventSignature" use="required" type="{http://www.w3.org/2001/XMLSchema}string"
 * />
 *       &lt;attribute name="severity" use="required" type="{http://www.w3.org/2001/XMLSchema}int"
 * />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "severityNode")
public class SeverityNode {

  @XmlAttribute(name = "eventSignature", required = true)
  protected String eventSignature;
  @XmlAttribute(name = "severity", required = true)
  protected int severity;

  /**
   * Gets the value of the eventSignature property.
   *
   * @return possible object is {@link String }
   */
  public String getEventSignature() {
    return eventSignature;
  }

  /**
   * Sets the value of the eventSignature property.
   *
   * @param value allowed object is {@link String }
   */
  public void setEventSignature(String value) {
    this.eventSignature = value;
  }

  /**
   * Gets the value of the severity property.
   */
  public int getSeverity() {
    return severity;
  }

  /**
   * Sets the value of the severity property.
   */
  public void setSeverity(int value) {
    this.severity = value;
  }

}
