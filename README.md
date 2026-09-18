# Aiven `auth-for-apache-kafka` — live PoC: DENY rule with absent `principal_type` is silently dropped

**In-scope asset:** `github.com/Aiven-Open/auth-for-apache-kafka`
**Audited commit:** `34cf5fb110fbbc33a21773305b3c6e88868ed994`
**Class:** Improper authorization / fail-open DENY (CWE-863)
**Evidence:** executed against the **real** `AivenAclAuthorizerV2` and
`AclAivenToNativeConverter` from upstream, in CI, not a reimplementation.

## Root cause

`AclAivenToNativeConverter.convert()` returns an empty list unless the ACL's
`principalType` is exactly `"User"`:

```java
if (aivenAcl.resourceRePattern != null) { return result; }        // empty
if (!Objects.equals(aivenAcl.principalType, "User")) { return result; } // empty
```

`AivenAclAuthorizerV2.calculateAuthorizeByResourceType()` builds the set of
forbidden patterns **only** from `convert()`:

```java
for (final AivenAcl acl : this.cacheReference.get().getDenyAclEntries()) {
    ... // host / resourceType / principal / operation all match
    for (final AclBinding binding : AclAivenToNativeConverter.convert(acl)) { ... }
}
```

The authorizer's own matcher treats a missing `principal_type` as “any
principal” (`AivenAcl.matchPrincipal`):

```java
if (this.principalType == null || this.principalType.equals(principalType)) { ... }
```

So a DENY that omits `principal_type` (intended to apply to everyone) matches
the request, reaches `convert()`, yields nothing, and is never added to the
deny set. The matching ALLOW then wins and the request is **ALLOWED**.

## What the CI run proves

| Scenario | `principal_type` on the DENY | Result | Correct result |
|---|---|---|---|
| Control | `"User"` | **DENIED** | DENIED ✅ |
| Exploit | absent | **ALLOWED** | DENIED ❌ |

The test asserts the *buggy* result so the demonstration is green and
unambiguous; the control asserts secure behaviour. See the workflow log lines
`[CONTROL]` / `[BUG]` / `[convert]`.

## Reproduce (one command, no local toolchain)

Push / run the `aiven-auth-kafka-deny-bypass-poc` workflow — it clones upstream
at the audited commit, drops in `DenyBypassLivePoC.java`, and runs:

```
./gradlew test --tests 'io.aiven.kafka.auth.DenyBypassLivePoC'
```

## Fix

Do not derive DENY (or ALLOW) patterns from a converter that cannot represent
the rule. Either make `convert()` handle a null/other `principalType`, or make
the authorizer treat an unconvertible DENY as a hard DENY (fail closed) and log it.
