package org.qubership.kafka.security.authorization;

import java.util.Set;
import javax.annotation.Nonnull;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.metadata.authorizer.StandardAcl;
import org.apache.kafka.metadata.authorizer.StandardAuthorizerData;
import org.apache.kafka.security.authorizer.AclEntry;

class AclMatcher {

  public static boolean match(AclEntry acl, @Nonnull String permissionType, String operation,
      String host, String requestPrincipalType, Set<String> requestPrincipalNames) {
    return match(permissionType, acl.permissionType().name(), operation, acl.operation(),
        host, acl.host(), AclEntry.WILDCARD_HOST, requestPrincipalNames, requestPrincipalType,
        acl.kafkaPrincipal);
  }

  public static boolean match(StandardAcl acl, @Nonnull String permissionType, String operation,
      String host, String requestPrincipalType, Set<String> requestPrincipalNames) {
    return match(permissionType, acl.permissionType().name(), operation, acl.operation(),
        host, acl.host(), StandardAuthorizerData.WILDCARD, requestPrincipalNames,
        requestPrincipalType, acl.kafkaPrincipal());
  }

  private static boolean match(String permissionType, String aclPermissionType,
      String operation, AclOperation aclOperation, String host, String aclHost,
      String hostWildcard, Set<String> requestPrincipalNames, String requestPrincipalType,
      KafkaPrincipal aclPrincipal) {
    if (permissionType.equalsIgnoreCase(aclPermissionType)
        && matchOperation(operation, aclOperation)
        && matchHost(host, aclHost, hostWildcard)) {
      for (String requestPrincipalName : requestPrincipalNames) {
        if (matchPrincipal(requestPrincipalType, requestPrincipalName, aclPrincipal)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean matchPrincipal(String requestPrincipalType, String requestPrincipalName,
      KafkaPrincipal aclPrincipal) {
    return requestPrincipalType.equalsIgnoreCase(aclPrincipal.getPrincipalType())
        && (requestPrincipalName.equalsIgnoreCase(aclPrincipal.getName())
        || Constants.WILDCARD.equals(aclPrincipal.getName()));
  }

  private static boolean matchOperation(String operation, AclOperation aclOperation) {
    return operation.equalsIgnoreCase(aclOperation.name()) || AclOperation.ALL.equals(aclOperation);
  }

  private static boolean matchHost(String host, String aclHost, String hostWildcard) {
    return host.equalsIgnoreCase(aclHost) || hostWildcard.equals(aclHost);
  }

  private AclMatcher() {}
}
