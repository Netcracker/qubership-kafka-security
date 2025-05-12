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

package org.qubership.kafka.security.authorization;

import static org.apache.kafka.metadata.authorizer.StandardAuthorizer.SUPER_USERS_CONFIG;

import org.qubership.kafka.security.audit.AuditRecordWriter;
import org.qubership.kafka.security.audit.records.AuthorizationAuditRecord;
import org.qubership.kafka.security.oauthbearer.OAuthKafkaPrincipal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.utils.SecurityUtils;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

interface ExtendedAuthorizer {
  Logger LOGGER = LoggerFactory.getLogger(ExtendedAuthorizer.class);

  String EMPTY_ACL_LOG = "No ACL found for resource [{}], authorized = {}";
  String AUTH_RESULT_LOG =
      "Principal = [{}] is {} Operation = [{}] from host = [{}] on resource = [{}]";
  String ALLOWED = "Allowed";
  String DENIED = "Denied";

  boolean aclsAllowAccess(AclOperation operation, ResourcePattern resource, String host,
      String requestPrincipalType, Set<String> requestPrincipalNames);

  boolean isSuperUser(KafkaPrincipal principal);

  default AuthorizationResult customAuthorizeAction(AuthorizableRequestContext requestContext,
      Action action) {
    KafkaPrincipal principal = requestContext.principal();
    String principalName = principal.getName();
    String host = requestContext.clientAddress().getHostAddress();
    AclOperation operation = action.operation();
    ResourcePattern resource = action.resourcePattern();
    LOGGER.trace("Context is {}, principal name is {}, principal type is {}, host is {}, "
            + "operation is {}, resource is {}",
        requestContext, principalName, principal.getPrincipalType(), host, operation, resource);

    if (Constants.ANONYMOUS.equalsIgnoreCase(principalName)) {
      LOGGER.info("No ACL found for cluster authorization, user: {}", principalName);
      return AuthorizationResult.DENIED;
    }

    // If Basic authentication is used, 'User' principal type is looked for in ACLs. For OAuth
    // authentication 'Role' principal type should be looked for.
    String requestPrincipalType = Constants.USER_PRINCIPAL_TYPE;
    Set<String> requestPrincipalNames = Collections.singleton(principalName);
    if (principal instanceof OAuthKafkaPrincipal) {
      requestPrincipalType = Constants.ROLE_PRINCIPAL_TYPE;
      requestPrincipalNames = ((OAuthKafkaPrincipal) principal).getToken().roles();
    }

    // To successfully compare the current principal with superusers, it must be of KafkaPrincipal
    // class. So, it is necessary to bring it to the desired form.
    boolean isSuperUser = isSuperUser(
        new KafkaPrincipal(principal.getPrincipalType(), principalName));
    LOGGER.trace("User {} is super user: {}", principal, isSuperUser);

    boolean authorized = isSuperUser
        || aclsAllowAccess(operation, resource, host, requestPrincipalType,
        requestPrincipalNames);

    logAuthResult(authorized, principal, operation, host, resource);
    return authorized ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED;
  }

  default void logAuthResult(boolean authorized, KafkaPrincipal principal, AclOperation operation,
      String host, ResourcePattern resource) {
    if (authorized) {
      LOGGER.trace(AUTH_RESULT_LOG, principal, ALLOWED, operation, host, resource);
    } else {
      LOGGER.warn(AUTH_RESULT_LOG, principal, DENIED, operation, host, resource);
    }
    AuditRecordWriter.getInstance().trackAuditEvent(
        new AuthorizationAuditRecord(principal,
            host,
            operation,
            resource,
            authorized)
    );
  }

  default Set<String> getOperationsByAclOperation(String operationName) {
    Set<String> operations = new HashSet<>();
    operations.add(operationName);
    if (Constants.DESCRIBE.equalsIgnoreCase(operationName)) {
      operations.add(Constants.READ);
      operations.add(Constants.WRITE);
      operations.add(Constants.DELETE);
      operations.add(Constants.ALTER);
    } else if (Constants.DESCRIBE_CONFIGS.equalsIgnoreCase(operationName)) {
      operations.add(Constants.ALTER_CONFIGS);
    }
    return operations;
  }

  default Set<String> getSuperUsers(Map<String, ?> configs) {
    Object configValue = configs.get(SUPER_USERS_CONFIG);
    if (configValue == null) {
      return Collections.emptySet();
    }
    String[] configValues = configValue.toString().split(";");
    Set<String> superUsers = new HashSet<>();
    for (String value : configValues) {
      String user = value.trim();
      if (!user.isEmpty()) {
        SecurityUtils.parseKafkaPrincipal(user);
        superUsers.add(user);
      }
    }
    return superUsers;
  }

}
