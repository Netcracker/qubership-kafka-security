package org.qubership.kafka.security.oauthbearer;

import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthBearerLoginCallbackHandler extends AbstractOAuthBearerCallbackHandler {
  private static final Logger LOGGER =
          LoggerFactory.getLogger(OAuthBearerLoginCallbackHandler.class);

  private final TokenRetriever retriever;

  public OAuthBearerLoginCallbackHandler() {
    this(new OAuthTokenRetriever());
  }

  public OAuthBearerLoginCallbackHandler(TokenRetriever retriever) {
    this.retriever = retriever;
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    throwExceptionIfNotConfigured();
    for (Callback callback: callbacks) {
      if (callback instanceof OAuthBearerTokenCallback) {
        OAuthBearerTokenCallback tokenCallback = (OAuthBearerTokenCallback) callback;
        if (tokenCallback.token() != null) {
          throw new IllegalArgumentException("Callback had a token already");
        }
        tokenCallback.token(retrieveToken());
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  @Nullable
  private OAuthBearerToken retrieveToken() {
    if (!retriever.isConfigured()) {
      return null;
    }
    String accessToken = retriever.retrieveAccessToken();
    if (accessToken == null) {
      throw new IllegalStateException(
              String.format("Access token not retrieved from: %s", retriever.getIdpEndpoint()));
    }
    OAuthBearerJwt jwt = new OAuthBearerJwt(accessToken);
    LOGGER.info("Retrieved token with principal: {}", jwt.principalName());
    return jwt;
  }

  @Override
  void configureOptions(@Nonnull Map<String, String> options) {
    retriever.configure(options);
  }

  @Override
  public void close() {
    retriever.close();
  }
}