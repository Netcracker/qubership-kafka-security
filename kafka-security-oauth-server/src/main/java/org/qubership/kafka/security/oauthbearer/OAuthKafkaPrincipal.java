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

package org.qubership.kafka.security.oauthbearer;

import javax.annotation.Nonnull;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

public class OAuthKafkaPrincipal extends KafkaPrincipal {

  @Nonnull
  private final OAuthBearerJwt token;

  public OAuthKafkaPrincipal(String principalType, String name, OAuthBearerJwt token) {
    super(principalType, name);
    this.token = token;
  }

  public OAuthBearerJwt getToken() {
    return token;
  }

  @Override
  public String toString() {
    return String.format("%s,Roles:%s", super.toString(), String.join(",", getToken().roles()));
  }
}
