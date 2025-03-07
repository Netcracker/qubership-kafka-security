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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jwt.proc.BadJWTException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.junit.Before;
import org.junit.Test;

public class OAuthBearerValidatorCallbackHandlerTest {

  private static final OAuthBearerJwt validToken = new OAuthBearerJwt(
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOSFpUQ1hDSlFpVVRQcFZiWW91TG42M3E4aW02UU1ZaUVTR2xEb3dodm53In0.eyJleHAiOjE1OTI0MDA0MTUsImlhdCI6MTU5MjQwMDM1NSwianRpIjoiODg4MmRlMDItMzZlNS00M2YxLThiOTAtMzY1MDRlOGY0ZTdkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDkwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI0Zjk3ODQxNC1jYTdjLTQ5ZDItOWI0NS1lNzYwMzc3ZmM0ZjMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJrYWZrYS10ZXN0Iiwic2Vzc2lvbl9zdGF0ZSI6IjZmNDlkMDQ5LTg4ZGQtNDQwMC05NGM3LWU2MzljOTJmY2FhNyIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImNsaWVudElkIjoia2Fma2EtdGVzdCIsImNsaWVudEhvc3QiOiIxNzIuMTguMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQta2Fma2EtdGVzdCIsImNsaWVudEFkZHJlc3MiOiIxNzIuMTguMC4xIn0.W1iQwap8hXhrZEmi4hCiUajpuJxHXUfZjQoCsBK9gW67mwr1O65iwBVuDuDPyPQw5vE8Lyo7g3y_A6jm9b2-NWS3Fhjql870Pq1IEibfbMVl5bMkivcBgqtus1pBXxXHW_7gzBsHtC2X1lHbFDAEl1UnYJa2OGMfyocSUbHUj-IYAeMHj6gmZzT5EKzdgWzJBFHGle-5YrEMen8tixwf53OxKBrK3NmFQRB8AaU1zqNjD1NOtwkDOf_n83jT-uKKb4oxgI9yrMMPvj6mvxNSYZdjEIWBPRRnvVYl89V-bV8UHq8iwDIyelBGrp-HU0JErHQPl5j7-668l6iZ1qXhWQ",
      "");
  private static final OAuthBearerJwt invalidToken = new OAuthBearerJwt(
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOSFpUQ1hDSlFpVVRQcFZiWW91TG42M3E4aW02UU1ZaUVTR2xEb3dodm53In0.eyJleHAiOjE1OTI0MDA0MTUsImlhdCI6MTU5MjQwMDM1NSwianRpIjoiODg4MmRlMDItMzZlNS00M2YxLThiOTAtMzY1MDRlOGY0ZTdkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDkwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI0Zjk3ODQxNC1jYTdjLTQ5ZDItOWI0NS1lNzYwMzc3ZmM0ZjMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJrYWZrYS10ZXN0Iiwic2Vzc2lvbl9zdGF0ZSI6IjZmNDlkMDQ5LTg4ZGQtNDQwMC05NGM3LWU2MzljOTJmY2FhNyIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsiYWRtaW4iLCJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SWQiOiJrYWZrYS10ZXN0IiwiY2xpZW50SG9zdCI6IjE3Mi4xOC4wLjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1rYWZrYS10ZXN0IiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4xOC4wLjEifQ.W1iQwap8hXhrZEmi4hCiUajpuJxHXUfZjQoCsBK9gW67mwr1O65iwBVuDuDPyPQw5vE8Lyo7g3y_A6jm9b2-NWS3Fhjql870Pq1IEibfbMVl5bMkivcBgqtus1pBXxXHW_7gzBsHtC2X1lHbFDAEl1UnYJa2OGMfyocSUbHUj-IYAeMHj6gmZzT5EKzdgWzJBFHGle-5YrEMen8tixwf53OxKBrK3NmFQRB8AaU1zqNjD1NOtwkDOf_n83jT-uKKb4oxgI9yrMMPvj6mvxNSYZdjEIWBPRRnvVYl89V-bV8UHq8iwDIyelBGrp-HU0JErHQPl5j7-668l6iZ1qXhWQ",
      "");

  private Map<String, String> options = new HashMap<>();

  @Before
  public void setUp() throws Exception {
    options.put("idpWhitelist",
        "[{'external': 'http://localhost:8090/auth/realms/master','internal':'http://keycloak:8080/auth/realms/master'}]");
    options.put("jwkSourceType", "keystore");
    options.put("keystorePath", this.getClass().getResource("test_keystore.jks").getPath());
    options.put("keystorePassword", "changeit");
    options.put("clockSkew", String.valueOf(Integer.MAX_VALUE));
  }

  @Test
  public void verifyValidTokenWithKeystore() throws Exception {
    OAuthBearerValidatorCallbackHandler validatorCallbackHandler = new OAuthBearerValidatorCallbackHandler();
    validatorCallbackHandler.configureOptions(options);

    OAuthBearerToken oAuthBearerToken = validatorCallbackHandler.validateToken(validToken);
    assertTrue(oAuthBearerToken instanceof OAuthBearerJwt);
  }

  @Test(expected = BadJWSException.class)
  public void verifyInvalidTokenWithKeystore() throws Exception {
    OAuthBearerValidatorCallbackHandler validatorCallbackHandler = new OAuthBearerValidatorCallbackHandler();
    validatorCallbackHandler.configureOptions(options);

    validatorCallbackHandler.validateToken(invalidToken);
    fail("Token validation should fail");
  }

  @Test(expected = BadJWTException.class)
  public void verifyExpiredTokenWithKeystore() throws Exception {
    OAuthBearerValidatorCallbackHandler validatorCallbackHandler = new OAuthBearerValidatorCallbackHandler();
    options.put("clockSkew", "0");
    validatorCallbackHandler.configureOptions(options);

    validatorCallbackHandler.validateToken(validToken);
    fail("Token validation should fail");
  }

  @Test(expected = IOException.class)
  public void verifyValidTokenWithInvalidKeystorePassword() throws Exception {
    OAuthBearerValidatorCallbackHandler validatorCallbackHandler = new OAuthBearerValidatorCallbackHandler();
    options.put("keystorePassword", "invalid");
    validatorCallbackHandler.configureOptions(options);

    validatorCallbackHandler.validateToken(validToken);
    fail("Token validation should fail");
  }
}
