package org.qubership.kafka.security.oauthbearer;

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.security.auth.login.AppConfigurationEntry;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;

abstract class AbstractOAuthBearerCallbackHandler implements AuthenticateCallbackHandler {
  private boolean configured = false;

  /**
   * Throws {@link IllegalStateException exception} if this instance has not been configured.
   */
  void throwExceptionIfNotConfigured() {
    if (!configured) {
      throw new IllegalStateException("Callback handler not configured");
    }
  }

  @Override
  public void configure(
      Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
    if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism)) {
      throw new IllegalArgumentException(
          String.format("Unexpected SASL mechanism: %s", saslMechanism));
    }
    if (requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null) {
      throw new IllegalArgumentException(
          String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
              jaasConfigEntries.size()));
    }
    @SuppressWarnings("unchecked")
    Map<String, String> options = (Map<String, String>) jaasConfigEntries.get(0).getOptions();
    configureOptions(Collections.unmodifiableMap(options));
    configured = true;
  }

  abstract void configureOptions(@Nonnull Map<String, String> options);

  @Override
  public void close() {
  }
}
