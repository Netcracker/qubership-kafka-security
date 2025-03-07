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

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.Test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Application;

import static org.junit.Assert.assertEquals;

public class OAuthBearerLoginCallbackHandlerTest extends JerseyTest {

  @Override
  protected Application configure() {
    return new ResourceConfig(HelloResource.class);
  }

  @Test
  public void test() throws Exception {
    String hello = target("hello").request().get(String.class);
    assertEquals("Hello World!", hello);
  }

  @Path("hello")
  public static class HelloResource {

    @GET
    public String getHello() {
      return "Hello World!";
    }
  }
}
