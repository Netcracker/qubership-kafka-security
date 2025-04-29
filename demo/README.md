# How to run demo

If you need to test changes in `Kafka security`, build `jar` file using the following command in terminal:

```
mvn clean install --settings=.mvn/settings.xml
```

Then add the volume to the Kafka configuration, that replaces the old jar with the one just created.
For example,

```
volumes:
  - ../kafka-security-oauth-server/target/kafka-security-oauth-server-0.10.0-3.8.0-SNAPSHOT.jar:/opt/kafka/libs/kafka-security-oauth-server-2.7.1-3.1.jar
  - ../kafka-security-oauth-client/target/kafka-security-oauth-client-0.10.0-3.8.0-SNAPSHOT.jar:/opt/kafka/libs/kafka-security-oauth-client-2.7.1-3.1.jar
```

To run the demo, you need to perform the following command in terminal:

```
docker-compose up -d
```

## Register Kafka Client in Identity Provider

When Identity Provider is ready to work, navigate to `http://localhost:8080/swagger`.

To register new OAuth2 client, go to `Identity Provider - OAuth2` -> `POST /register` and specify the
following parameters:

- `Authorization` is an initial access token. It should be filled with `Bearer default_client_registration_secret` value.
- `data` is data for new OAuth2 client in JSON format. For example,
  ```json
  {
    "client_name": "Kafka",
    "redirect_uris": ["string"],
    "grant_types": ["client_credentials"],
    "scope": "Administrator Kafka Client"
  }
  ```

Then press the `Try it out!` button.

After successful execution of the request, do not forget to save necessary information from response body:

```
{
  "client_id": "040e5206-670b-4021-bc16-5b4431b47733",
  "client_secret": "G7duTVWlPT2EQCAHuqhgzj-sOUqjMysQRZgR_gV1tj3UtJuuAuL523SOsksNmwILQmgOdx8BCk2VYldyF60AAA",
  "client_secret_expires_at": 0,
  "client_id_issued_at": 1610532645,
  "registration_access_token": "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiIwNDBlNTIwNi02NzBiLTQwMjEtYmMxNi01YjQ0MzFiNDc3MzMiLCJpc3MiOiJodHRwOlwvXC9pZGVudGl0eS1wcm92aWRlcjo4MDgwXC8iLCJpYXQiOjE2MTA1MzI2NDUsImp0aSI6IjA0MzUzNjQ1LWMzNzAtNDJjZS1iNzBkLWJmMjEyMDBiNTg2MiJ9.dH9gtLZF9WtRGjciG9UlI08ETVoyEACV3p9sXy9yDQuwOZhWwZuSSVmYlBeZLs2oYwZUYJ3JXBTqMrEekL1LAOPlR9JHsAQNbiqNDSBy6y_seP8YtzSlMzLV-VsGZRP8IvaEVIZIohNuTG4Ou2CJub28thIuN50MQZVqBYra3A63D9stPGMZTe8H53zvtjrrC9h52HZB_b-HrUJfnbigyQvacWJH9WvP_dBV9hnU-nYbbhpq2tSaNSKrcnW8mBXJqx9aPTpyLbaVfPURMqzMTdsgNKGRBCUWFfXBhd_1sl1zmu_GYzapwEf9NcZd3dWbkAUxx5mJ9LgYB-dt_KSntA",
  "registration_client_uri": "http://identity-provider:8080/register/040e5206-670b-4021-bc16-5b4431b47733",
  "redirect_uris": [
    "string"
  ],
  "client_name": "Kafka",
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "Kafka Client Administrator",
  "grant_types": [
    "client_credentials"
  ]
}
```

You may need `client_id` and `client_secret` parameters.

## Run Authentication Tests

Navigate to the `kafka-security-oauth-client/src/test/java/org/qubership/kafka/security/oauthbearer/OAuthExample.java`
file in IntelliJ IDEA, specify correct values for `CLIENT_ID` and `CLIENT_SECRET` parameters from
[Register Kafka Client in Identity Provider](#register-kafka-client-in-identity-provider) section and
run `main` method of the class.
`SCRAM` tests should be executed successfully, but `OAUTHBEARER` tests will fail because necessary ACLs are
not configured in Kafka. For more information, see [Configure ACLs](#configure-acls) section.

## Configure ACLs

For proper work of Kafka with OAuth2.0 it is necessary to configure access control lists (ACLs) which
contain information about permissions for specific principals.

First of all, connect to Kafka in `docker-compose` using the following commands:

```
$ docker ps
```

```
$ docker exec -ti demo_kafka_1 /bin/bash
bash-5.0$
```

```
$ cd /opt/kafka/
```

Then, create a file with properties to connect to Kafka (`adminclient.properties`). For example,

```
$ cat > config/adminclient.properties
sasl.mechanism=SCRAM-SHA-512
security.protocol=SASL_PLAINTEXT
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="admin" password="admin";
```

Now you can create all manner of ACLs you need. Here are some variants as an example:

- Create allowing ACLs for `Role:User` principal as producer and consumer. In this scenario `OAUTHBEARER`
  tests fail because the created OAuth2 client (`040e5206-670b-4021-bc16-5b4431b47733`) does not have
  `User` role.

  ```
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --add --allow-principal Role:User --producer --topic kafka-oauth-example-topic
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --add --allow-principal Role:User --consumer --topic kafka-oauth-example-topic --group kafka-oauth-example-group
  ```

- Create allowing ACLs for `Role:Administrator` principal as producer and consumer. In this scenario `OAUTHBEARER`
  tests succeed because the created OAuth2 client (`040e5206-670b-4021-bc16-5b4431b47733`) has `Administrator` role.

  ```
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --add --allow-principal Role:Administrator --producer --topic kafka-oauth-example-topic
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --add --allow-principal Role:Administrator --consumer --topic kafka-oauth-example-topic --group kafka-oauth-example-group
  ```

- Create denying ACL for `Role:Client` principal coming from `10.0.2.2` IP. In this scenario `OAUTHBEARER`
  tests fail because the created OAuth2 client (`040e5206-670b-4021-bc16-5b4431b47733`) has `Client`
  role and comes from `10.0.2.2` IP.

  ```
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --add --deny-principal Role:Client --deny-host 10.0.2.2 --operation Write --topic kafka-oauth-example-topic
  ```

- Delete denying ACL for `Role:Client` principal coming from `10.0.2.2` IP. In this scenario `OAUTHBEARER`
  tests succeed because the created OAuth2 client (`040e5206-670b-4021-bc16-5b4431b47733`) has only allowing
  ACLs.

  ```
  $ bin/kafka-acls.sh --bootstrap-server localhost:9092 --command-config ./config/adminclient.properties --remove --deny-principal Role:Client --deny-host 10.0.2.2 --operation Write --topic kafka-oauth-example-topic
  ```

## Run Authentication Tests With Vault as IdP

### Configure Vault as IdP

Vault supposed to be installed in some Kubernetes environment and has `Kubernetes Authentication method` to login in the Vault.
To use the Vault as IdP, it should have `/identity/oidc/{key}` and `/identity/oidc/{role}` Vault secret paths mounted, and
client application which is installed to the Kubernetes environment must be able to read the `/identity/oidc/{role}`
endpoint. To match a Vault policy with necessary capabilities on Vault secret path, client application must use predefined
Vault Kubernetes Auth role. To declare all this parts you can use `VaultConfig` Kubernetes Custom Resource (supposed, that
in Vault operator the `Vault Configurator` is turned on).

```
apiVersion: qubership.org/v1
kind: VaultConfig
metadata:
  name: <cr_name>
spec:
  policies:
    - name: <policy_name>
      rules: |-
        path "/identity/oidc/+/*" {
            capabilities = ["create", "read", "update", "delete", "list"]
        }
  auth:
    kubernetes:
      roles:
        - name: <auth_role>
          settings:
            bound_service_account_names: <application_service_account_name>
            bound_service_account_namespaces: <application_namespace>
            policies: <policy_name>
            ttl: 1h
  secret:
    oidc:
      keys:
        - name: <application_oidc_name>
          settings:
            rotation_period: 12h
            verification_ttl: 12h
            allowed_client_ids: "*"
      roles:
        - name: <application_oidc_role>
          settings:
            key: <application_oidc_name>
            ttl: 12h
```

Where,

- `<cr_name>` is unique name of VaultConfig within application namespace.
- `<policy_name>` is name of Vault policy.
- `<auth_role>` is name of Vault Kubernetes Authentication role.
- `<application_service_account_name>` is name of application service account.
- `<application_namespace>` is name of application Kubernetes namespace.
- `<application_oidc_name>` is name of Vault OpenId Connect key.
- `<application_oidc_role>` is name of Vault OpenId Connect role.

To perform tests, follow the steps below.

1. Choose any service account which has already existed in the same Kubernetes environment as Vault Service.
2. Get the service account Kubernetes token and remember it.
3. Create the `VaultConfig` CR as cr.yaml file. For instance,

```
apiVersion: qubership.org/v1
kind: VaultConfig
metadata:
  name: kafka-client-config
spec:
  policies:
    - name: kafka-client-oidc
      rules: |-
        path "/identity/oidc/+/*" {
            capabilities = ["create", "read", "update", "delete", "list"]
        }
  auth:
    kubernetes:
      roles:
        - name: kafka-client-role
          settings:
            bound_service_account_names: elasticsearch-service-operator
            bound_service_account_namespaces: opendistro
            policies: kafka-client-oidc
            ttl: 1h
  secret:
    oidc:
      keys:
        - name: kafka-client-oidc-key
          settings:
            rotation_period: 12h
            verification_ttl: 12h
            allowed_client_ids: "*"
      roles:
        - name: kafka-client-role-oidc
          settings:
            key: kafka-client-oidc-key
            ttl: 12h
```

and apply it in the application namespace via

```
kubectl apply -f cr.yaml -n <namespace>
```

4. Remember the following specified variables:
   - `VAULT_ROLE_PATH` = `<namespace>-<name>-secret.roles[0].name` (`opendistro-kafka-client-config-kafka-client-role-oidc` in the example).
   - `VAULT_AUTH_ROLE` = `<namespace>-<name>-auth.kuberetes.roles[0].name` (`opendistro-kafka-client-config-kafka-client-role` in the example).

### Run Authentication Tests

- Restart docker-compose with `ENABLE_AUTHORIZATION=false` Kafka environment variable and be sure that `IDP_WHITELIST` Kafka
  environment variable contains correct internal and external path to the Vault Kubernetes service (by default, we have
  `{'internal': 'http://host.docker.internal:8200/v1/identity/oidc','external':'http://vault-service.vault-service:8200/v1/identity/oidc'}`)
- Navigate to the `kafka-security-oauth-client/src/test/java/org/qubership/kafka/security/oauthbearer/OAuthExample.java`
  file in IntelliJ IDEA, specify correct values for `VAULT_ROLE_PATH`, `VAULT_AUTH_ROLE` parameters from
  [Configure Vault as IdP](#configure-vault-as-idp) section (st. 4).
- Specify `KUBERNETES_SERVICE_ACCOUNT_TOKEN` environment variable for OAuthExample.java and set value from
  [Configure Vault as IdP](#configure-vault-as-idp) section (st. 2).
- Organize port forwarding between Kubernetes Vault and localhost machine via the following command:
  ```
  kubectl port-forward service/vault-service 8200:8200 -n <vault_namespace>
  ```
  If you specify another port, please, change `VAULT_URL` variable value in the OAuthExample.java class.
- Run `main` method of the class.
  `SCRAM` and `VAULTOAUTHBEARER` tests should be executed successfully.
