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
