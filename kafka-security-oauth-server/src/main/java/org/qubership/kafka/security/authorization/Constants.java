package org.qubership.kafka.security.authorization;

public class Constants {

  public static final String WILDCARD = "*";

  public static final String ANONYMOUS = "ANONYMOUS";

  public static final String ALLOW = "Allow";
  public static final String DENY = "Deny";
  public static final String DESCRIBE = "Describe";
  public static final String READ = "Read";
  public static final String WRITE = "Write";
  public static final String DELETE = "Delete";
  public static final String ALTER = "Alter";
  public static final String DESCRIBE_CONFIGS = "DescribeConfigs";
  public static final String ALTER_CONFIGS = "AlterConfigs";

  // Acl Types
  public static final String USER_PRINCIPAL_TYPE = "User";
  public static final String ROLE_PRINCIPAL_TYPE = "Role";

  // Properties attributes
  // If set to true when no ACLs are found for a resource, authorizer allows access to everyone.
  // Defaults to false.
  public static final String ALLOW_EVERYONE_IF_NO_ACL_FOUND = "allow.everyone.if.no.acl.found";
}
