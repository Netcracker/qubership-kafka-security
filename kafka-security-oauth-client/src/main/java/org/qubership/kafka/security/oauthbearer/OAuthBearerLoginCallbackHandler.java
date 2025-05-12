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