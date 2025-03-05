package org.qubership.kafka.security.authorization;

import org.qubership.kafka.security.audit.AuditConstants;
import org.qubership.kafka.security.audit.AuditRecordWriter;
import org.qubership.kafka.security.audit.records.AuthenticationAuditRecord;
import org.qubership.kafka.security.oauthbearer.OAuthBearerJwt;
import org.qubership.kafka.security.oauthbearer.OAuthKafkaPrincipal;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.message.DefaultPrincipalData;
import org.apache.kafka.common.protocol.ByteBufferAccessor;
import org.apache.kafka.common.protocol.MessageUtil;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExtendedKafkaPrincipalBuilder implements KafkaPrincipalBuilder, KafkaPrincipalSerde {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExtendedKafkaPrincipalBuilder.class);

  private static final String OAUTH_BEARER_TOKEN_PROPERTY = "OAUTHBEARER.token";

  /**
   * Constructs a new instance.
   */
  public ExtendedKafkaPrincipalBuilder() {
  }

  @Override
  public KafkaPrincipal build(AuthenticationContext context) {
    LOGGER.debug("Used authentication context is {}", context);
    if (context instanceof PlaintextAuthenticationContext) {
      AuditRecordWriter.getInstance().trackAuditEvent(
          AuthenticationAuditRecord.successful(KafkaPrincipal.ANONYMOUS.getName(),
              AuditConstants.ANONYMOUS_AUTHENTICATION_TYPE,
              context.clientAddress().getHostAddress())
      );
      return KafkaPrincipal.ANONYMOUS;
    } else if (context instanceof SslAuthenticationContext) {
      SSLSession sslSession = ((SslAuthenticationContext) context).session();
      LOGGER.debug("Session for SslAuthenticationContext is {}", sslSession);
      try {
        KafkaPrincipal principal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE,
            sslSession.getPeerPrincipal().getName());
        AuditRecordWriter.getInstance().trackAuditEvent(
            AuthenticationAuditRecord.successful(principal.getName(),
                AuditConstants.SSL_AUTHENTICATION_TYPE,
                context.clientAddress().getHostAddress())
        );
        return principal;
      } catch (SSLPeerUnverifiedException se) {
        LOGGER.debug("Peer is not authenticated: ", se);
        AuditRecordWriter.getInstance().trackAuditEvent(
            AuthenticationAuditRecord.successful(KafkaPrincipal.ANONYMOUS.getName(),
                AuditConstants.ANONYMOUS_AUTHENTICATION_TYPE,
                context.clientAddress().getHostAddress())
        );
        return KafkaPrincipal.ANONYMOUS;
      }
    } else if (context instanceof SaslAuthenticationContext) {
      SaslServer saslServer = ((SaslAuthenticationContext) context).server();
      LOGGER.debug("Server for SaslAuthenticationContext is {}", saslServer);
      OAuthBearerToken token =
          (OAuthBearerToken) saslServer.getNegotiatedProperty(OAUTH_BEARER_TOKEN_PROPERTY);
      if (token == null) {
        KafkaPrincipal principal = new KafkaPrincipal(KafkaPrincipal.USER_TYPE,
            saslServer.getAuthorizationID());
        AuditRecordWriter.getInstance().trackAuditEvent(
            AuthenticationAuditRecord.successful(principal.getName(),
                saslServer.getMechanismName(),
                context.clientAddress().getHostAddress())
        );
        return principal;
      } else {
        OAuthBearerJwt jwt = token instanceof OAuthBearerJwt
            ? (OAuthBearerJwt) token : new OAuthBearerJwt(token.value());
        LOGGER.debug("OAuth Bearer JWT is {}", jwt);
        KafkaPrincipal principal = new OAuthKafkaPrincipal(KafkaPrincipal.USER_TYPE,
            saslServer.getAuthorizationID(),
            jwt);
        AuditRecordWriter.getInstance().trackAuditEvent(
            AuthenticationAuditRecord.successful(principal.getName(),
                saslServer.getMechanismName(),
                context.clientAddress().getHostAddress())
        );
        return principal;
      }
    } else {
      throw new IllegalArgumentException(
          "Unhandled authentication context type: " + context.getClass().getName());
    }
  }

  @Override
  public byte[] serialize(KafkaPrincipal principal) {
    DefaultPrincipalData data = new DefaultPrincipalData()
            .setType(principal.getPrincipalType())
            .setName(principal.getName())
            .setTokenAuthenticated(principal.tokenAuthenticated());
    return MessageUtil.toVersionPrefixedBytes(DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION, data);
  }

  @Override
  public KafkaPrincipal deserialize(byte[] bytes) {
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    short version = buffer.getShort();
    if (version < DefaultPrincipalData.LOWEST_SUPPORTED_VERSION
            || version > DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION) {
      throw new SerializationException("Invalid principal data version " + version);
    }

    DefaultPrincipalData data = new DefaultPrincipalData(new ByteBufferAccessor(buffer), version);
    return new KafkaPrincipal(data.type(), data.name(), data.tokenAuthenticated());
  }
}
