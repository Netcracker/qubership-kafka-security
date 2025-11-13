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

import java.util.Set;
import javax.annotation.Nonnull;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.metadata.authorizer.StandardAcl;
import org.apache.kafka.metadata.authorizer.StandardAuthorizerData;
import org.apache.kafka.security.authorizer.AclEntry;

final class AclMatcher {

  private AclMatcher() {}

  public static boolean match(AclBinding acl,
                              @Nonnull String permissionType,
                              String operation,
                              String host,
                              String requestPrincipalType,
                              Set<String> requestPrincipalNames) {

    AccessControlEntry e = acl.entry();
    return matchInternal(
        permissionType,
        e.permissionType().name(),
        operation,
        e.operation(),
        host,
        e.host(),
        StandardAuthorizerData.WILDCARD,
        requestPrincipalType,
        requestPrincipalNames,
        e.principal(),
        null
    );
  }

  public static boolean match(StandardAcl acl,
                              @Nonnull String permissionType,
                              String operation,
                              String host,
                              String requestPrincipalType,
                              Set<String> requestPrincipalNames) {

    return matchInternal(
        permissionType,
        acl.permissionType().name(),
        operation,
        acl.operation(),
        host,
        acl.host(),
        StandardAuthorizerData.WILDCARD,
        requestPrincipalType,
        requestPrincipalNames,
        null,
        acl.kafkaPrincipal()
    );
  }


  private static boolean matchInternal(String expectedPermissionType,
                                       String aclPermissionType,
                                       String expectedOperation,
                                       AclOperation aclOperation,
                                       String requestHost,
                                       String aclHost,
                                       String hostWildcard,
                                       String requestPrincipalType,
                                       Set<String> requestPrincipalNames,
                                       String aclPrincipalStrOrNull,
                                       KafkaPrincipal aclKafkaPrincipal) {

    if (!equalsIgnoreCaseSafe(expectedPermissionType, aclPermissionType)) {
      return false;
    }
    if (!matchOperation(expectedOperation, aclOperation)) {
      return false;
    }
    if (!matchHost(requestHost, aclHost, hostWildcard)) {
      return false;
    }

    if (aclKafkaPrincipal != null) {
      for (String reqName : requestPrincipalNames) {
        if (matchPrincipalKafka(requestPrincipalType, reqName, aclKafkaPrincipal)) {
          return true;
        }
      }
      return false;
    } else {
      for (String reqName : requestPrincipalNames) {
        if (matchPrincipalString(requestPrincipalType, reqName, aclPrincipalStrOrNull)) {
          return true;
        }
      }
      return false;
    }
  }

  private static boolean matchPrincipalKafka(String reqType,
                                             String reqName,
                                             KafkaPrincipal aclPrincipal) {
    if (aclPrincipal == null) return false;

    if (!equalsIgnoreCaseSafe(reqType, aclPrincipal.getPrincipalType())
        && !StandardAuthorizerData.WILDCARD.equals(aclPrincipal.getPrincipalType())) {
      return false;
    }

    return StandardAuthorizerData.WILDCARD.equals(aclPrincipal.getName())
        || equalsIgnoreCaseSafe(reqName, aclPrincipal.getName());
  }

  private static boolean matchPrincipalString(String reqType,
                                              String reqName,
                                              String aclPrincipalStr) {
    if (aclPrincipalStr == null || aclPrincipalStr.isEmpty()) return false;

    if (AclEntry.WILDCARD_HOST.equals(aclPrincipalStr)) return true;

    String aclType;
    String aclName;

    int idx = aclPrincipalStr.indexOf(':');
    if (idx > 0) {
      aclType = aclPrincipalStr.substring(0, idx);
      aclName = aclPrincipalStr.substring(idx + 1);
    } else {
      aclType = reqType;
      aclName = aclPrincipalStr;
    }

    if (!equalsIgnoreCaseSafe(reqType, aclType) && !AclEntry.WILDCARD_HOST.equals(aclType)) {
      return false;
    }

    return AclEntry.WILDCARD_HOST.equals(aclName) || equalsIgnoreCaseSafe(reqName, aclName);
  }


  private static boolean matchOperation(String expectedOperation, AclOperation aclOperation) {
    return equalsIgnoreCaseSafe(expectedOperation, aclOperation.name())
        || AclOperation.ALL.equals(aclOperation);
  }

  private static boolean matchHost(String requestHost, String aclHost, String hostWildcard) {
    return equalsIgnoreCaseSafe(requestHost, aclHost) || equalsIgnoreCaseSafe(aclHost, hostWildcard);
  }


  private static boolean equalsIgnoreCaseSafe(String a, String b) {
    return a == null ? b == null : a.equalsIgnoreCase(b);
  }
}
