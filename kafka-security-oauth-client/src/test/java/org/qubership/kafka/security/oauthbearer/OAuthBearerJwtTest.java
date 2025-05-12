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

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class OAuthBearerJwtTest {

  private static final String INVALID_TOKEN = "4OTEsImp0aSI6IjE5NDIxZTI0LWE4Y2ItNDg4Mi05";
  private static final String VALID_TOKEN = "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIxMTE"
      + "iLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiQWRtaW5pc3RyYXRvciIsIlJPTEVfQURNSU5JU1RSQVRPUiIsIlJPT"
      + "EVfQURNSU4iLCJUZW5hbnQgTWFuYWdlciIsIlN5c3RlbSBBZG1pbmlzdHJhdG9yIl19LCJhenAiOiI5YzJkYjE0ZS0"
      + "zOTU3LTRlZTktYTYxNS1kYWQyMGU4YWQ1NTEiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIiwiaXNzIjoiaHR0cDpcL"
      + "1wvaWRlbnRpdHktcHJvdmlkZXI6ODA4MFwvIiwidHlwIjoiQmVhcmVyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic3l"
      + "zYWRtIiwiZXhwIjoxNTY4MDQyNDA1LCJzZXNzaW9uX3N0YXRlIjoiYThiMDJhMWY1NzFhYjYxODBlZjI2YzQ5NDQ0Y"
      + "zVhOGMiLCJpYXQiOjE1NjgwMzg4MDUsImp0aSI6ImYxZDJkODI1LTMyMzEtNGZlNy1iMzU5LTM5YWJkMjdkYjZmZCI"
      + "sInRlbmFudC1pZCI6ImRlZmF1bHQifQ.rRqmTx7bxv4FHQ-03TegVhT3nlHqC_VgL0KSOPhBEGILymgd-o79T89bvg"
      + "J0G2s2PxmGLETvEMbsfv9ULiYRMwSm5IWZ4r0H7cBb2EXAO3r29JqHqgMSAjQ0MgsfYbK8gjpRP7TxxrrtRJAN_hwm"
      + "8b8lT7SEDs2Y0LC_hyjlv26FwXLg93EpG66EK4GQEdtGImIRdYz8tfRfttSyT-S5CJQQl7sIDSa_wL2-vtc614VXVC"
      + "v-Blcm1Bj7LlpH5BFAYi9WjOv4LkG7GII7C78jIBq3ueEKs7ESN9LSwcJM5eW3tcXwNpcXXUhrvaATmQHoePv40A-R"
      + "rzPk6q_bWa1WDw";
  private static final String REALM_ACCESS_ROLES_PATH = "realm_access.roles";
  private static final String SCOPE_PATH = "scope";


  @Test(expected = IllegalArgumentException.class)
  public void testCreateWithInvalidJwtTokenStructure() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(INVALID_TOKEN);
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckValue() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.value(), equalTo(VALID_TOKEN));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckLifetimeMs() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.lifetimeMs(), equalTo(1568042405000L));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckPrincipalName() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.principalName(), equalTo("111"));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckStartTimeMs() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.startTimeMs(), equalTo(1568038805000L));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckAlgorithm() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.algorithm().getName(), equalTo("RS256"));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckIssuer() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.issuer(), equalTo("http://identity-provider:8080/"));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckEmptyRoles() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN);
    assertThat(jwt.roles(), equalTo(Collections.emptySet()));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckRolesList() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN, REALM_ACCESS_ROLES_PATH);
    String[] expectedRoles = {"Administrator", "ROLE_ADMINISTRATOR", "ROLE_ADMIN", "Tenant Manager",
        "System Administrator"};
    assertThat(jwt.roles(), equalTo(new HashSet<>(Arrays.asList(expectedRoles))));
  }

  @Test
  public void testCreateWithValidJwtTokenStructureAndCheckPlainRoles() {
    OAuthBearerJwt jwt = new OAuthBearerJwt(VALID_TOKEN, SCOPE_PATH);
    String[] expectedRoles = {"openid", "profile"};
    assertThat(jwt.roles(), equalTo(new HashSet<>(Arrays.asList(expectedRoles))));
  }
}
