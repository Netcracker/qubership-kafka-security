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

import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.createClient;
import static org.qubership.kafka.security.oauthbearer.OAuthLoginUtils.normalizeUrl;
import static java.util.Objects.requireNonNull;

import org.qubership.kafka.security.audit.AuditConstants;
import org.qubership.kafka.security.audit.AuditRecordWriter;
import org.qubership.kafka.security.audit.records.AuthenticationAuditRecord;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthBearerValidatorCallbackHandler extends AbstractOAuthBearerCallbackHandler {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(OAuthBearerValidatorCallbackHandler.class);

  private static final String CLOCK_SKEW = "clockSkew";
  private static final String JWKS_CONNECTION_TIMEOUT = "jwksConnectionTimeout";
  private static final String JWKS_READ_TIMEOUT = "jwksReadTimeout";
  private static final String JWKS_SIZE_LIMIT = "jwksSizeLimit";
  private static final String IDP_WHITELIST = "idpWhitelist";
  private static final String TOKEN_ROLES_PATH = "tokenRolesPath";
  private static final String JWK_SOURCE_TYPE = "jwkSourceType";
  private static final String KEYSTORE_PATH = "keystorePath";
  private static final String KEYSTORE_PASSWORD = "keystorePassword";
  private static final String KEYSTORE_TYPE = "keystoreType";

  private static final String JWKS_SOURCE_TYPE = "jwks";
  private static final String KEYSTORE_SOURCE_TYPE = "keystore";

  private static final String TOKEN_ROLES_PATH_DEFAULT_VALUE = "resource_access.account.roles";
  private static final String JWK_SOURCE_TYPE_DEFAULT_VALUE = JWKS_SOURCE_TYPE;
  private static final String KEYSTORE_PATH_DEFAULT_VALUE = "/opt/kafka/config/public_certs.jks";
  private static final String KEYSTORE_TYPE_DEFAULT_VALUE = "JKS";
  private static final boolean REPLACE_HOST_AND_PORT =
          getBooleanEnv("REPLACE_INTERNAL_HOST_ENABLED");

  @Nonnull
  private final ConcurrentMap<String, JWKSource<SecurityContext>> jwks = new ConcurrentHashMap<>();

  private JWTClaimsSetVerifier<SecurityContext> claimsVerifier;
  private int jwksConnectionTimeout;
  private int jwksReadTimeout;
  private int jwksSizeLimit;
  private IdentityProviderUrlResolver identityProviderUrlResolver;
  private String tokenRolesPath;
  private String jwkSourceType;
  private String keystorePath;
  private String keystorePassword;
  private String keystoreType;
  private Client client;

  private static boolean getBooleanEnv(String key) {
    String env = System.getenv(key);
    return env == null ? false : "true".equals(env);
  }

  @Nonnull
  private static JWTClaimsSetVerifier<SecurityContext> createClaimsVerifier(int maxClockSkew) {
    DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>();
    claimsVerifier.setMaxClockSkew(maxClockSkew);
    return claimsVerifier;
  }

  private static int extractInt(
      @Nonnull Map<String, String> options, @Nonnull String key, int defaultValue) {
    String value = options.get(key);
    return (value == null || value.isEmpty()) ? defaultValue : Integer.parseInt(value);
  }

  static String replaceHostAndPort(String internal, String external) throws URISyntaxException {
    URI externalUri = new URI(external);
    String externalHost = externalUri.getHost();
    int externalPort = externalUri.getPort();
    URI internalUri = new URI(internal);
    return UriBuilder
            .fromUri(internalUri)
            .host(externalHost)
            .port(externalPort)
            .build()
            .toString();
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    throwExceptionIfNotConfigured();
    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerValidatorCallback) {
        OAuthBearerValidatorCallback validatorCallback = (OAuthBearerValidatorCallback) callback;
        String tokenValue = validatorCallback.tokenValue();
        if (tokenValue == null) {
          throw new IllegalArgumentException("Callback missing required token value");
        }
        OAuthBearerJwt jwt = null;
        try {
          jwt = new OAuthBearerJwt(tokenValue, tokenRolesPath);
          validatorCallback.token(validateToken(jwt));
        } catch (MalformedURLException | URISyntaxException e) {
          error(validatorCallback,
              "There is no response from Identity Provider with particular URL", e, jwt);
        } catch (ParseException e) {
          error(validatorCallback,
              "Key selector cannot parse resource which contains public key", e, jwt);
        } catch (BadJOSEException e) {
          error(validatorCallback, "Cannot verify token using wrong algorithm", e, jwt);
        } catch (JOSEException e) {
          error(validatorCallback, "Cannot verify token with wrong signature", e, jwt);
        } catch (IssuerNotTrustedException e) {
          error(validatorCallback, "Token issuer URL is not compliance with whitelist", e, jwt);
        } catch (IOException | GeneralSecurityException e) {
          error(validatorCallback, "Cannot obtain public certificate from keystore", e, jwt);
        } catch (RuntimeException e) {
          error(validatorCallback, "Cannot verify token with non-JWT structure", e, jwt);
        }
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  private void error(
      @Nonnull OAuthBearerValidatorCallback callback,
      @Nonnull String description,
      @Nonnull Exception e,
      OAuthBearerJwt jwt) {
    LOGGER.error(description, e);
    AuditRecordWriter.getInstance().trackAuditEvent(
        AuthenticationAuditRecord.failed(jwt != null ? jwt.principalName() : null,
            AuditConstants.OAUTH_AUTHENTICATION_TYPE, description,
            null)
    );
    callback.error(description, null, null);
  }

  @Nonnull
  protected OAuthBearerToken validateToken(@Nonnull OAuthBearerJwt jwt)
      throws IOException, URISyntaxException, BadJOSEException, ParseException,
      JOSEException, IssuerNotTrustedException, GeneralSecurityException {
    String identityProviderUrl = identityProviderUrlResolver.resolveUrl(jwt.issuer());
    JWKSource<SecurityContext> keySource = jwks.get(identityProviderUrl);
    if (keySource == null) {
      if (KEYSTORE_SOURCE_TYPE.equalsIgnoreCase(jwkSourceType)) {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        char[] password = keystorePassword != null ? keystorePassword.toCharArray() : null;
        keyStore.load(new FileInputStream(keystorePath), password);
        JWKSet jwkSet = JWKSet.load(keyStore, null);
        keySource = new ImmutableJWKSet<>(jwkSet);
      } else {
        String jwkUri = getJwkFromOpenIdConfig(identityProviderUrl);
        ResourceRetriever resourceRetriever =
            new DefaultResourceRetriever(jwksConnectionTimeout, jwksReadTimeout, jwksSizeLimit);
        keySource = new RemoteJWKSet<>(new URL(jwkUri), resourceRetriever);
      }
      JWKSource<SecurityContext> previousKeySource =
          jwks.putIfAbsent(identityProviderUrl, keySource);
      if (previousKeySource != null) {
        keySource = previousKeySource;
      }
    }
    verifySignature(keySource, jwt.algorithm(), jwt.value());
    LOGGER.info("Successfully validated token with principal: {}", jwt.principalName());
    return jwt;
  }

  @Nonnull
  private String getJwkFromOpenIdConfig(@Nonnull String identityProviderUrl)
      throws URISyntaxException {
    String jwkUri = getJwkEndpointUrl(identityProviderUrl);
    if (jwkUri == null || jwkUri.isEmpty()) {
      throw new IllegalArgumentException("jwks_uri does not present in openid configuration");
    }
    if (jwkUri.startsWith("/")) {
      jwkUri = normalizeUrl(identityProviderUrl + jwkUri);
    }

    if (REPLACE_HOST_AND_PORT) {
      jwkUri = replaceHostAndPort(jwkUri, identityProviderUrl);
    }

    LOGGER.trace("jwk uri from openid configuration: {}", jwkUri);
    return jwkUri;
  }

  @Nullable
  private String getJwkEndpointUrl(@Nonnull String identityProviderUrl) throws URISyntaxException {
    String configurationUrl =
        normalizeUrl(identityProviderUrl + "/.well-known/openid-configuration");
    WebTarget webTarget = client.target(configurationUrl);
    @SuppressWarnings("unchecked")
    Map<String, String> response =
        webTarget.request(MediaType.APPLICATION_JSON_TYPE).get(Map.class);
    requireNonNull(response,
        () -> String.format(
            "JWK endpoint cannot be obtained: invalid response from: %s", configurationUrl));
    return response.get("jwks_uri");
  }

  private void verifySignature(
      @Nonnull JWKSource<SecurityContext> keySource,
      @Nonnull JWSAlgorithm expectedAlgorithm,
      @Nonnull String token)
      throws ParseException, BadJOSEException, JOSEException {
    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelectorExtended<>(expectedAlgorithm, keySource);
    ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(keySelector);
    processor.setJWTClaimsSetVerifier(claimsVerifier);
    processor.process(token, null);
  }

  @Override
  void configureOptions(@Nonnull Map<String, String> options) {
    int clockSkew = extractInt(options, CLOCK_SKEW, 10);
    claimsVerifier = createClaimsVerifier(clockSkew);
    jwksConnectionTimeout = extractInt(options, JWKS_CONNECTION_TIMEOUT, 1000);
    jwksReadTimeout = extractInt(options, JWKS_READ_TIMEOUT, 1000);
    jwksSizeLimit = extractInt(options, JWKS_SIZE_LIMIT, 51200);
    String idpWhitelist = options.get(IDP_WHITELIST);
    identityProviderUrlResolver = IdentityProviderUrlResolver.create(idpWhitelist);
    tokenRolesPath = options.getOrDefault(TOKEN_ROLES_PATH, TOKEN_ROLES_PATH_DEFAULT_VALUE);
    jwkSourceType = options.getOrDefault(JWK_SOURCE_TYPE, JWK_SOURCE_TYPE_DEFAULT_VALUE);
    if (!KEYSTORE_SOURCE_TYPE.equalsIgnoreCase(jwkSourceType)) {
      client = createClient(LOGGER);
    }
    keystorePath = options.getOrDefault(KEYSTORE_PATH, KEYSTORE_PATH_DEFAULT_VALUE);
    keystorePassword = options.get(KEYSTORE_PASSWORD);
    keystoreType = options.getOrDefault(KEYSTORE_TYPE, KEYSTORE_TYPE_DEFAULT_VALUE);

    AuditRecordWriter.getInstance().configure(options);
  }

  @Override
  public void close() {
    if (client != null) {
      client.close();
    }
  }
}
