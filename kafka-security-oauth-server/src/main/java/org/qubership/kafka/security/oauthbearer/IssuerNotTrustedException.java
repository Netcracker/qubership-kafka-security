package org.qubership.kafka.security.oauthbearer;

import javax.annotation.Nonnull;

/**
 * Exception for case when issuer from JWT token is not trusted for application and cannot be
 * resolved by whitelist and rules.
 */
final class IssuerNotTrustedException extends Exception {

  private static final String ISSUER_IS_NOT_TRUSTED_MSG = "Issuer url '%s' is not found in "
      + "whitelist of Identity Provider and cannot be used";

  @Nonnull
  private final String issuer;

  /**
   * Default constructor for exception.
   *
   * @param issuer untrusted issuer url
   */
  IssuerNotTrustedException(@Nonnull String issuer) {
    super(String.format(ISSUER_IS_NOT_TRUSTED_MSG, issuer));
    this.issuer = issuer;
  }

  /**
   * Returns untrusted issuer.
   *
   * @return issuer url
   */
  @Nonnull
  String issuer() {
    return issuer;
  }
}
