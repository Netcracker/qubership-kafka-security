# qubership-kafka-security

## Overview

Kafka Security is library that adds various security extensions to Kafka. There are two parts of this library - "client"
and "server". The "client" part is enough for Kafka client applications to interact with Kafka via OAuth protocol. The
"server" part validates keys of OAuth JWTs and performs authorization and audit logs within Kafka.

## How to Use Library

### Kafka Authorization

#### Server Configuration

If you want to enable Kafka authorization, it is necessary to add specific properties in
`server.properties`.

If you use Kafka with Zookeeper, then you need to add the following properties:
```properties
authorizer.class.name=org.qubership.kafka.security.authorization.ExtendedAclAuthorizer
principal.builder.class=org.qubership.kafka.security.authorization.ExtendedKafkaPrincipalBuilder
super.users=User:${ADMIN_USERNAME}
```

If you use Kafka with KRaft, then you need to the following properties:
```properties
authorizer.class.name=org.qubership.kafka.security.authorization.ExtendedStandardAuthorizer
principal.builder.class=org.qubership.kafka.security.authorization.ExtendedKafkaPrincipalBuilder
super.users=User:${ADMIN_USERNAME}
```

### OAuth

#### Client Configuration For Common Identity Provider

Configure the following properties in `producer.properties` or `consumer.properties`:
```
sasl.mechanism=OAUTHBEARER
security.protocol=SASL_PLAINTEXT
sasl.login.callback.handler.class=org.qubership.kafka.security.oauthbearer.OAuthBearerLoginCallbackHandler
```

Configure the JAAS configuration property. Clients may configure JAAS using the client configuration 
property `sasl.jaas.config` or using the static JAAS config file.

1. **JAAS configuration using client configuration property**

    Configure the JAAS configuration property in `producer.properties` or `consumer.properties`:
    ```
    sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId="${CLIENT_ID}" clientSecret="${CLIENT_SECRET}" tokenEndpoint="${TOKEN_ENDPOINT}";
    ```
2. **JAAS configuration using static config file**

    Add a JAAS config file with a client login section named `KafkaClient`:
    ```
    KafkaClient {
        org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required
        clientId="${CLIENT_ID}"
        clientSecret="${CLIENT_SECRET}"
        tokenEndpoint="${TOKEN_ENDPOINT}";
    };
    ```
    Pass the JAAS config file location as JVM parameter (`-Djava.security.auth.login.config`) 
    to each client JVM.

* `CLIENT_ID` is OAuth2 client identifier issued to it during the registration process.
* `CLIENT_SECRET` is OAuth2 client secret issued to it during the registration process.
* `TOKEN_ENDPOINT` is token endpoint used to request tokens.

#### Client Configuration For Vault Identity Provider

Configure the following properties in `producer.properties` or `consumer.properties`:
```
sasl.mechanism=OAUTHBEARER
security.protocol=SASL_PLAINTEXT
sasl.login.callback.handler.class=org.qubership.kafka.security.oauthbearer.VaultOAuthBearerLoginCallbackHandler
```

Configure the JAAS configuration property. Clients may configure JAAS using the client configuration 
property `sasl.jaas.config` or using the static JAAS config file.

1. **JAAS configuration using client configuration property**

    Configure the JAAS configuration property in `producer.properties` or `consumer.properties`:
    ```
    sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required vaultRolePath="${VAULT_ROLE_PATH}" vaultAuthRole="${VAULT_AUTH_ROLE}" vaultUrl="${VAULT_URL}";
    ```
    For example,
    ```
    sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required vaultRolePath=kafka-staging-kafka-staging-config-kafka-staging-oidc vaultAuthRole=kafka-staging-kafka-staging-config-kafka-staging-auth vaultUrl=http://vault-service.vault-service:8200;
    ```
    where `kafka-staging` application is deployed to `kafka-staging` namespace, has `kafka-staging-config` VaultConfig resource name, `kafka-staging-auth` auth role and `kafka-staging-auth` oidc role in the VaultConfig.
2. **JAAS configuration using static config file**

    Add a JAAS config file with a client login section named `KafkaClient`:
    ```
    KafkaClient {
        org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required
        vaultRolePath="${VAULT_ROLE_PATH}"
        vaultAuthRole="${VAULT_AUTH_ROLE}"
        vaultUrl="${VAULT_URL}";
    };
    ```
    Pass the JAAS config file location as JVM parameter (`-Djava.security.auth.login.config`) 
    to each client JVM.

    * `${VAULT_ROLE_PATH}` is an OpenID Connect (oidc) role which has been already specified in the Vault.
    * `${VAULT_AUTH_ROLE}` is a Vault Kubernetes Auth method role which has already been specified in the Vault. 
    * `${VAULT_URL}` is Vault root endpoint used to request tokens.
    
    For example,
    ```
    KafkaClient {
        org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required
        vaultRolePath=kafka-staging-kafka-staging-config-kafka-staging-oidc
        vaultAuthRole=kafka-staging-kafka-staging-config-kafka-staging-auth
        vaultUrl=http://vault-service.vault-service:8200;
    };
    ```
    where `kafka-staging` application is deployed to `kafka-staging` namespace, has `kafka-staging-config` VaultConfig resource name, `kafka-staging-auth` auth role and `kafka-staging-auth` oidc role in the VaultConfig.

#### Server Configuration

Configure the following properties in `server.properties`:
```
listener.security.protocol.map=CLIENT:SASL_PLAINTEXT
sasl.enabled.mechanisms=OAUTHBEARER
listener.name.client.oauthbearer.sasl.login.callback.handler.class=org.qubership.kafka.security.oauthbearer.OAuthBearerLoginCallbackHandler
listener.name.client.oauthbearer.sasl.server.callback.handler.class=org.qubership.kafka.security.oauthbearer.OAuthBearerValidatorCallbackHandler
listener.name.client.oauthbearer.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clockSkew="${CLOCK_SKEW}" jwksConnectionTimeout="${JWKS_CONNECTION_TIMEOUT}" jwksReadTimeout="${JWKS_READ_TIMEOUT}" jwksSizeLimit="${JWKS_SIZE_LIMIT}" idpWhitelist="${IDP_WHITELIST}" tokenRolesPath="${TOKEN_ROLES_PATH}" auditLogsEnabled="${AUDIT_LOGS_ENABLED} auditCefConfigPath="${AUDIT_CEF_CONFIG_PATH}";
```

* `CLOCK_SKEW` is time in seconds during which expired access token is valid.
* `JWK_SOURCE_TYPE` is type of the source for Public Keys which are used for OAuth token validation. There are two possible values:
    * `jwks` - Kafka uses JWKS endpoint of Identity Provider to obtain public keys.
    * `keystore` - Kafka uses internal Java keystore to obtain public certificates. 
    
    The default value is `jwks`.
* `JWKS_CONNECTION_TIMEOUT` is time in milliseconds to connect to IdP JWKS endpoint. Should be specified only if `JWK_SOURCE_TYPE` is `jwks`.
* `JWKS_READ_TIMEOUT` is time in milliseconds to get response from IdP JWKS endpoint. Should be specified only if `JWK_SOURCE_TYPE` is `jwks`.
* `JWKS_SIZE_LIMIT` is maximum entity size in bytes to send to IdP JWKS endpoint. Should be specified only if `JWK_SOURCE_TYPE` is `jwks`.
* `KEYSTORE_PATH` is the path to keystore with public keys. The default value is `/opt/kafka/config/public_certs.jks`. Should be specified only if `JWK_SOURCE_TYPE` is `keystore`.
* `KEYSTORE_PASSWORD` is the password for keystore with public keys. Should be specified only if `JWK_SOURCE_TYPE` is `keystore`.
* `KEYSTORE_TYPE` is the type of keystore with public keys. The default value is `jks`. Should be specified only if `JWK_SOURCE_TYPE` is `keystore`.
* `IDP_WHITELIST` is whitelist of trusted identity provider issuers that can be used to verify 
  the OAuth2 access token signature.
* `TOKEN_ROLES_PATH` is the path to the field in the token where roles are specified.
* `AUDIT_LOGS_ENABLED` enables Kafka audit logs in CEF format when set to `true`. The default value is `false`.
* `AUDIT_CEF_CONFIG_PATH` is the path to audit log CEF XML configuration. The default value is `/opt/kafka/config/cef-configuration.xml`. Should be specified only if `AUDIT_LOGS_ENABLED` is `true`.