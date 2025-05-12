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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.apache.kafka.common.acl.AccessControlEntryFilter;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourcePatternFilter;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.metadata.authorizer.StandardAcl;
import org.apache.kafka.metadata.authorizer.StandardAuthorizer;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExtendedStandardAuthorizer extends StandardAuthorizer implements ExtendedAuthorizer {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExtendedStandardAuthorizer.class);

  private volatile Set<String> superUsers = new HashSet<>();

  private boolean shouldAllowEveryoneIfNoAclIsFound = false;

  @Override
  public void configure(Map<String, ?> javaConfigs) {
    LOGGER.debug("Configuration is {}", javaConfigs);
    shouldAllowEveryoneIfNoAclIsFound = Boolean
        .parseBoolean(String.valueOf(javaConfigs.get(Constants.ALLOW_EVERYONE_IF_NO_ACL_FOUND)));
    super.configure(javaConfigs);
    superUsers = getSuperUsers(javaConfigs);
  }

  @Override
  public List<AuthorizationResult> authorize(AuthorizableRequestContext requestContext,
      List<Action> actions) {
    return actions.stream().map(action -> customAuthorizeAction(requestContext, action))
        .collect(Collectors.toList());
  }

  /**
   * Operation is allowed if no ACLs are found and Kafka has configured to give access to all users
   * or if no deny ACLs are found and at least one allow ACLs matches.
   *
   * @param operation             type of operation client is trying to perform on resource
   * @param resource              resource the user is trying to access
   * @param host                  IP address
   * @param requestPrincipalType  principal type that is looked for in list of ACLs
   * @param requestPrincipalNames set of principal names that are looked for in list of ACLs
   * @return true if operation is allowed to the principal
   */
  public boolean aclsAllowAccess(AclOperation operation, ResourcePattern resource, String host,
      String requestPrincipalType, Set<String> requestPrincipalNames) {
    Set<StandardAcl> aclSet = getAclSetByResource(resource);
    LOGGER.debug("ACL set for resource {} is {}", resource, aclSet);
    return isAclEmptyAndEveryoneIsAllowed(aclSet, resource)
        || !denyAclExists(aclSet, operation, host, requestPrincipalType, requestPrincipalNames)
        && allowAclExists(aclSet, operation, host, requestPrincipalType, requestPrincipalNames);
  }

  @Override
  public boolean isSuperUser(KafkaPrincipal principal) {
    return superUsers.contains(principal.toString());
  }

  /**
   * Receives ACLs for specific resource in Java format.
   *
   * @param resource resource the user is trying to access
   * @return set of Standard ACL entries for resource
   */
  private Set<StandardAcl> getAclSetByResource(ResourcePattern resource) {
    AclBindingFilter filter = new AclBindingFilter(
        new ResourcePatternFilter(resource.resourceType(), resource.name(), PatternType.MATCH),
        AccessControlEntryFilter.ANY);
    Set<StandardAcl> aclSet = new HashSet<>();
    acls(filter).forEach(aclBinding -> aclSet.add(StandardAcl.fromAclBinding(aclBinding)));
    return aclSet;
  }

  /**
   * If no ACLs found for the resource, permission is determined by value of config
   * allow.everyone.if.no.acl.found.
   *
   * @param aclSet set of Standard ACL entries for the resource
   * @param resource    resource the user is trying to access
   * @return true if ACL set is empty and property 'allow.everyone.if.no.acl.found' has value 'true'
   */
  private boolean isAclEmptyAndEveryoneIsAllowed(Set<StandardAcl> aclSet,
      ResourcePattern resource) {
    if (aclSet.isEmpty()) {
      logAuthResultForEmptyAcl(resource);
      return shouldAllowEveryoneIfNoAclIsFound;
    }
    return false;
  }

  private void logAuthResultForEmptyAcl(ResourcePattern resource) {
    if (shouldAllowEveryoneIfNoAclIsFound) {
      LOGGER.trace(EMPTY_ACL_LOG, resource, shouldAllowEveryoneIfNoAclIsFound);
    } else {
      LOGGER.warn(EMPTY_ACL_LOG, resource, shouldAllowEveryoneIfNoAclIsFound);
    }
  }

  /**
   * Checks if there is any ACL that disallows the operation.
   *
   * @param aclSet                set of Standard ACL entries for the resource
   * @param operation             type of operation client is trying to perform on resource
   * @param host                  IP address
   * @param requestPrincipalType  principal type that is looked for in list of ACLs
   * @param requestPrincipalNames set of principal names that are looked for in list of ACLs
   * @return true if operation is denied for the principal
   */
  private boolean denyAclExists(Set<StandardAcl> aclSet, AclOperation operation, String host,
      String requestPrincipalType, Set<String> requestPrincipalNames) {
    return aclMatch(aclSet, Constants.DENY, operation.name(), host, requestPrincipalType,
        requestPrincipalNames);
  }

  /**
   * Checks if there are any ACLs which allow the operation. Allowing read, write, delete, or alter
   * implies allowing describe.
   *
   * @param aclSet                set of Standard ACL entries for the resource
   * @param operation             type of operation client is trying to perform on resource
   * @param host                  IP address
   * @param requestPrincipalType  principal type that is looked for in list of ACLs
   * @param requestPrincipalNames Set of principal names that are looked for in list of ACLs
   * @return true if operation is allowed for the principal
   */
  private boolean allowAclExists(Set<StandardAcl> aclSet, AclOperation operation, String host,
      String requestPrincipalType, Set<String> requestPrincipalNames) {
    Set<String> operations = getOperationsByAclOperation(operation.name());
    for (String op : operations) {
      if (aclMatch(aclSet, Constants.ALLOW, op, host, requestPrincipalType,
          requestPrincipalNames)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if there are any ACLs which match current configuration.
   *
   * @param aclSet                set of Standard ACL entries for the resource
   * @param permissionType        permission type of operation (Allow or Deny)
   * @param operation             type of operation client is trying to perform on resource
   * @param host                  IP address
   * @param requestPrincipalType  principal type that is looked for in list of ACLs
   * @param requestPrincipalNames set of principal names that are looked for in list of ACLs
   * @return true if match is found
   */
  private boolean aclMatch(Set<StandardAcl> aclSet, @Nonnull String permissionType,
      String operation, String host,
      String requestPrincipalType, Set<String> requestPrincipalNames) {
    for (StandardAcl acl : aclSet) {
      boolean match = AclMatcher.match(acl, permissionType, operation, host, requestPrincipalType,
          requestPrincipalNames);
      if (match) {
        LOGGER.debug("Operation = {} on resource from host = {} is {} based on ACL = {}",
            operation, host, permissionType, acl);
        return true;
      }
    }
    return false;
  }
}
