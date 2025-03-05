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
