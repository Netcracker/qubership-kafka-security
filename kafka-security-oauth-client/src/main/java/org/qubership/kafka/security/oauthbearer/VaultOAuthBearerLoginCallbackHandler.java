package org.qubership.kafka.security.oauthbearer;

public class VaultOAuthBearerLoginCallbackHandler extends OAuthBearerLoginCallbackHandler {
  public VaultOAuthBearerLoginCallbackHandler() {
    this(new VaultOAuthTokenRetriever());
  }

  public VaultOAuthBearerLoginCallbackHandler(TokenRetriever retriever) {
    super(retriever);
  }
}
