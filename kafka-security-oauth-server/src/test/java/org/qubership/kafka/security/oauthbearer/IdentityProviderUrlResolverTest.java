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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class IdentityProviderUrlResolverTest {

  @Test
  public void testResolveInternalUrlByExternalUrl() throws Exception {
    String whitelist = "[{'internal': 'http://internal:8080', 'external': 'http://external:80'}]";
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(whitelist);
    assertThat(
        "Internal url must be returned if whitelist has internal url for specified external url",
        resolver.resolveUrl("http://external:80"), equalTo("http://internal:8080"));
  }

  @Test
  public void testResolveExternalUrlIfNoInternalUrl() throws Exception {
    String whitelist = "[{'internal': 'http://internal:8080', 'external': 'http://external:80'},"
        + "{'external': 'http://external:81'}]";
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(whitelist);
    assertThat(
        "External url must be returned if whitelist has no internal url for specified external url",
        resolver.resolveUrl("http://external:81"), equalTo("http://external:81"));
  }

  @Test
  public void testResolveInternalUrl() throws Exception {
    String whitelist = "[{'internal': 'http://internal:8080', 'external': 'http://external:80'}]";
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(whitelist);
    assertThat("Internal url must be returned if whitelist has specified internal url",
        resolver.resolveUrl("http://internal:8080"), equalTo("http://internal:8080"));
  }

  @Test
  public void testResolveInternalUrlIfNoExternalUrl() throws Exception {
    String whitelist = "[{'internal': 'http://internal:8080', 'external': 'http://external:80'},"
        + "{'internal': 'http://internal:8081'}]";
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(whitelist);
    assertThat(
        "Internal url must be returned if whitelist has specified internal url "
            + "and has no external url",
        resolver.resolveUrl("http://internal:8081"), equalTo("http://internal:8081"));
  }

  @Test(expected = IssuerNotTrustedException.class)
  public void testThrowErrorIfUrlIsNotTrusted() throws Exception {
    String whitelist = "[{'internal': 'http://internal:8080', 'external': 'http://external:80'}]";
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(whitelist);
    resolver.resolveUrl("http://external:81");
  }

  @Test(expected = IssuerNotTrustedException.class)
  public void testThrowErrorIfWhitelistIsEmpty() throws Exception {
    IdentityProviderUrlResolver resolver = IdentityProviderUrlResolver.create(null);
    resolver.resolveUrl("http://external:81");
  }
}
