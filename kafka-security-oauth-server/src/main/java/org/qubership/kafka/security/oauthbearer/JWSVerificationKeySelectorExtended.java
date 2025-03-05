package org.qubership.kafka.security.oauthbearer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Extension for {@link JWSVerificationKeySelector} to allow matching key Ids in lower case.
 *
 * @param <C> security context
 */
public class JWSVerificationKeySelectorExtended<C extends SecurityContext>
    extends JWSVerificationKeySelector<C> {

  /**
   * Creates a new JWS verification key selector.
   *
   * @param jwsAlg The expected JWS algorithm for the objects to be verified. Must not be {@code null}.
   * @param jwkSource The JWK source. Must not be {@code null}.
   */
  public JWSVerificationKeySelectorExtended(JWSAlgorithm jwsAlg,
      JWKSource<C> jwkSource) {
    super(jwsAlg, jwkSource);
  }

  /**
   * Transforms parent's matcher to allow matching  key Ids in lower case. It's necessary because keystore stores key ID
   * as alias of certificate and alias can be in lower case only.
   *
   * @param jwsHeader The JWS header. Must not be {@code null}.
   * @return The JWK matcher, {@code null} if none could be created.
   */
  @Override
  protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {
    JWKMatcher jwkMatcher = super.createJWKMatcher(jwsHeader);
    for (String kid : jwkMatcher.getKeyIDs()) {
      jwkMatcher.getKeyIDs().add(kid.toLowerCase());
    }
    return jwkMatcher;
  }
}
