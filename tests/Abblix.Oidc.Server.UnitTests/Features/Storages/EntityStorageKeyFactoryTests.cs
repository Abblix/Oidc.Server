// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// The storage keys are a wire format: a running deployment holds records under the names this factory
/// produced yesterday, so changing one orphans them rather than renaming them.
/// </summary>
/// <remarks>
/// The revocation cutoff is the one where that costs most. Orphaning it does not lose data anybody notices -
/// it quietly un-revokes every suspended account and every ended session on deploy, with nothing failing.
/// </remarks>
public class EntityStorageKeyFactoryTests
{
    private static readonly IEntityStorageKeyFactory Factory = new EntityStorageKeyFactory();

    /// <summary>
    /// Every key the factory builds is in the space of the tenant it is built for, so two tenants storing the same
    /// entity never meet in the one storage they share. Each method of the factory is asked, a method added later
    /// included.
    /// </summary>
    [Fact]
    public void EveryKey_IsInTheSpaceOfTheTenantItIsBuiltFor()
    {
        var acme = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };
        var globex = new TenantDefinition { Id = "globex", Issuer = new Uri("https://auth.example.com/globex") };
        var methods = typeof(IEntityStorageKeyFactory).GetMethods();
        Assert.NotEmpty(methods);

        foreach (var method in methods)
        {
            var arguments = method.GetParameters().Skip(1).Select(parameter => SampleOf(parameter.ParameterType)).ToArray();
            var atAcme = (string)method.Invoke(Factory, [acme, .. arguments])!;
            var atGlobex = (string)method.Invoke(Factory, [globex, .. arguments])!;

            Assert.StartsWith(TenantKey.Of(acme, string.Empty), atAcme, StringComparison.Ordinal);
            Assert.StartsWith(TenantKey.Of(globex, string.Empty), atGlobex, StringComparison.Ordinal);
        }
    }

    private static object SampleOf(Type type)
    {
        if (type == typeof(string))
            return "x";
        if (type == typeof(int))
            return 1;
        if (type == typeof(long))
            return 1L;
        if (type == typeof(Uri))
            return new Uri("https://client.example.com/request");
        if (type == typeof(RevocationScope))
            return RevocationScope.Subject;

        throw new ArgumentOutOfRangeException(nameof(type), type, "No sample value for this parameter type in this test.");
    }

    [Theory]
    [InlineData(RevocationScope.Subject, "Abblix.Oidc.Server:Revoked:subject:user_42")]
    [InlineData(RevocationScope.Session, "Abblix.Oidc.Server:Revoked:session:user_42")]
    [InlineData(RevocationScope.ClientSubject, "Abblix.Oidc.Server:Revoked:client-subject:user_42")]
    public void RevocationCutoffKey_HasTheNameLiveRecordsAreHeldUnder(RevocationScope scope, string expected)
    {
        Assert.Equal(TenantKey.Of(SingleIssuer.Tenant, expected), Factory.RevocationCutoffKey(SingleIssuer.Tenant, scope, "user_42"));
    }

    /// <summary>
    /// A family's key cannot be spelled by another family with a different identifier inside it.
    /// </summary>
    /// <remarks>
    /// Identifiers come from generators a host replaces, so a value carrying another family's segment is
    /// an input that exists rather than one somebody must break in to supply. The danger is not two
    /// families disagreeing about one identifier - it is one family's key for an awkward identifier
    /// reading as another family's key for a plain one: nested under the request's own name, a next-poll
    /// key would be spelled exactly like the request key of a code beginning with that segment, and the
    /// poll would overwrite the authentication. Each family therefore starts with a segment of its own.
    /// <para>
    /// A row comparing one identifier across families cannot see this, and stayed green against the
    /// nested spelling.
    /// </para>
    /// </remarks>
    [Theory]
    // One segment, not two: nested under the request's own name, the schedule key for "abc" is spelled
    // exactly like the request key for "NextPoll:abc".
    [InlineData("NextPoll:abc", "abc")]
    [InlineData("NextPoll:CIBA:abc", "CIBA:abc")]
    public void ARequestKey_IsNeverSpelledLikeAScheduleKey(string awkward, string plain)
    {
        Assert.NotEqual(
            Factory.DeviceAuthorizationRequestKey(SingleIssuer.Tenant, awkward),
            Factory.DeviceAuthorizationNextPollKey(SingleIssuer.Tenant, plain));

        Assert.NotEqual(
            Factory.BackChannelAuthenticationRequestKey(SingleIssuer.Tenant, awkward),
            Factory.BackChannelAuthenticationNextPollKey(SingleIssuer.Tenant, plain));
    }

    /// <summary>
    /// A replay record cannot be spelled like a request key either.
    /// </summary>
    /// <remarks>
    /// The same shape one family over: this one puts a client identifier in the FIRST segment, so a client
    /// registered as "Device" spells a replay key exactly like the device request key of a code beginning
    /// "Reuse:". A client identifier is chosen at registration, which makes it an input that exists.
    /// </remarks>
    [Fact]
    public void AReplayRecord_IsNeverSpelledLikeARequestKey()
    {
        Assert.NotEqual(
            Factory.DeviceAuthorizationRequestKey(SingleIssuer.Tenant, "Reuse:code_challenge:a-hash"),
            Factory.AuthorizationValueReuseKey(SingleIssuer.Tenant, "Device", "code_challenge", "a-hash"));

        Assert.NotEqual(
            Factory.BackChannelAuthenticationRequestKey(SingleIssuer.Tenant, "Reuse:code_challenge:a-hash"),
            Factory.AuthorizationValueReuseKey(SingleIssuer.Tenant, "CIBA", "code_challenge", "a-hash"));
    }

    /// <summary>
    /// The record that a flow ended is never held under the key of a stored request, so writing it cannot replace
    /// a request still in flight.
    /// </summary>
    [Fact]
    public void ConsumedRequestUriKey_IsNeverSpelledLikeRequestKey()
    {
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:pushed");

        Assert.NotEqual(Factory.AuthorizationRequestKey(SingleIssuer.Tenant, requestUri), Factory.ConsumedRequestUriKey(SingleIssuer.Tenant, requestUri));
    }

    /// <summary>
    /// Distinct attempts from distinct sources never share a key, however the source is spelled.
    /// </summary>
    /// <remarks>
    /// The source is supplied by the caller and can carry colons, as an IPv6 address does.
    /// </remarks>
    [Fact]
    public void AnAttemptFromOneSource_IsNeverSpelledLikeAnotherSources()
    {
        var keys = new[]
        {
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "a1", 2, 3),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "a", 12, 3),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "a:1", 2, 3),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "a", 1, 23),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "::1", 5, 1),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "::1:5", 1, 1),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "x:Attempt:1", 2, 3),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, "x", 1, 2),
        };

        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// No two families name the same entry for one identifier either.
    /// </summary>
    [Fact]
    public void EveryFamily_NamesItsOwnEntry()
    {
        const string identifier = "abc";

        var keys = new[]
        {
            Factory.DeviceAuthorizationRequestKey(SingleIssuer.Tenant, identifier),
            Factory.DeviceAuthorizationNextPollKey(SingleIssuer.Tenant, identifier),
            Factory.BackChannelAuthenticationRequestKey(SingleIssuer.Tenant, identifier),
            Factory.BackChannelAuthenticationNextPollKey(SingleIssuer.Tenant, identifier),
            Factory.DeviceAuthorizationUserCodeKey(SingleIssuer.Tenant, identifier),
            Factory.UserCodeRateLimitAttemptKey(SingleIssuer.Tenant, identifier, life: "a-life", attempt: 1),
            Factory.AddressRateLimitAttemptKey(SingleIssuer.Tenant, identifier, 1, 1),
            Factory.AuthorizedGrantKey(SingleIssuer.Tenant, identifier),
            Factory.JsonWebTokenStatusKey(SingleIssuer.Tenant, identifier),
            Factory.AuthorizationValueReuseKey(SingleIssuer.Tenant, identifier, "code_challenge", "a-hash"),
            Factory.SessionClientsGenerationKey(SingleIssuer.Tenant, identifier),
            Factory.SessionClientKey(SingleIssuer.Tenant, identifier, identifier, 1),
            Factory.SessionClientMarkerKey(SingleIssuer.Tenant, identifier, identifier, identifier),
            Factory.SessionClientsRenewalKey(SingleIssuer.Tenant, identifier, identifier),
        };

        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// Every scope has a key, so a member added later fails here rather than at the throw inside the factory -
    /// which a request would reach first, as a fault in the middle of validating somebody's token.
    /// </summary>
    [Fact]
    public void RevocationCutoffKey_CoversEveryScope()
    {
        var scopes = Enum.GetValues<RevocationScope>();
        Assert.NotEmpty(scopes);

        var keys = scopes.Select(scope => Factory.RevocationCutoffKey(SingleIssuer.Tenant, scope, "user_42")).ToArray();

        // Distinct, because two scopes sharing a name would let a session revocation refuse a subject's
        // tokens, or the reverse - a collision no test of a single scope can see.
        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// A scope the factory does not know is refused loudly. Reading it as any existing scope would silently
    /// revoke the wrong principal.
    /// </summary>
    [Fact]
    public void RevocationCutoffKey_RefusesAnUnknownScope()
    {
        var unknown = (RevocationScope)int.MaxValue;

        Assert.Throws<ArgumentOutOfRangeException>(() => Factory.RevocationCutoffKey(SingleIssuer.Tenant, unknown, "user_42"));
    }

    /// <summary>
    /// A key built from a credential carries a digest of it: the store's listings and its client's faults quote keys,
    /// and must not hand out an authorization code, a CIBA request id, a device code or a user code.
    /// </summary>
    [Fact]
    public void AKeyBuiltFromACredential_DoesNotCarryIt()
    {
        const string credential = Credential;

        string[] keys =
        [
            Factory.AuthorizedGrantKey(SingleIssuer.Tenant, credential),
            Factory.BackChannelAuthenticationRequestKey(SingleIssuer.Tenant, credential),
            Factory.BackChannelAuthenticationNextPollKey(SingleIssuer.Tenant, credential),
            Factory.DeviceAuthorizationRequestKey(SingleIssuer.Tenant, credential),
            Factory.DeviceAuthorizationNextPollKey(SingleIssuer.Tenant, credential),
            Factory.DeviceAuthorizationUserCodeKey(SingleIssuer.Tenant, credential),
            Factory.UserCodeRateLimitAttemptKey(SingleIssuer.Tenant, credential, "life", 1),
            Factory.UserCodeRateLimitGenerationKey(SingleIssuer.Tenant, credential),
        ];

        Assert.All(keys, key => Assert.DoesNotContain(credential, key, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Every node and every later version builds the same key for the same credential, which is what lets one of them
    /// find the entry another wrote. Pinned to the digest itself, so a key that differed per process or changed its
    /// spelling between versions fails here rather than in a cluster.
    /// </summary>
    [Theory]
    [InlineData(nameof(IEntityStorageKeyFactory.AuthorizedGrantKey), "Abblix.Oidc.Server:Grant:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.BackChannelAuthenticationRequestKey), "Abblix.Oidc.Server:CIBA:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.BackChannelAuthenticationNextPollKey), "Abblix.Oidc.Server:NextPoll:CIBA:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.DeviceAuthorizationRequestKey), "Abblix.Oidc.Server:Device:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.DeviceAuthorizationNextPollKey), "Abblix.Oidc.Server:NextPoll:Device:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.DeviceAuthorizationUserCodeKey), "Abblix.Oidc.Server:UserCode:" + CredentialDigest)]
    [InlineData(nameof(IEntityStorageKeyFactory.UserCodeRateLimitGenerationKey), "Abblix.Oidc.Server:RateLimit:UserCode:" + CredentialDigest + ":Generation")]
    public void AKeyBuiltFromACredential_IsItsDigestUnderTheEntryName(string method, string expected)
    {
        var key = method switch
        {
            nameof(IEntityStorageKeyFactory.AuthorizedGrantKey) => Factory.AuthorizedGrantKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.BackChannelAuthenticationRequestKey) => Factory.BackChannelAuthenticationRequestKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.BackChannelAuthenticationNextPollKey) => Factory.BackChannelAuthenticationNextPollKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationRequestKey) => Factory.DeviceAuthorizationRequestKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationNextPollKey) => Factory.DeviceAuthorizationNextPollKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationUserCodeKey) => Factory.DeviceAuthorizationUserCodeKey(SingleIssuer.Tenant, Credential),
            nameof(IEntityStorageKeyFactory.UserCodeRateLimitGenerationKey) => Factory.UserCodeRateLimitGenerationKey(SingleIssuer.Tenant, Credential),
            _ => throw new ArgumentOutOfRangeException(nameof(method), method, "No such key method in this test"),
        };

        Assert.Equal(TenantKey.Of(SingleIssuer.Tenant, expected), key);
    }

    [Fact]
    public void AnAttemptKeyOfAUserCode_IsItsDigestUnderTheEntryName()
        => Assert.Equal(
            TenantKey.Of(SingleIssuer.Tenant, "Abblix.Oidc.Server:RateLimit:UserCode:" + CredentialDigest + ":life:Attempt:1"),
            Factory.UserCodeRateLimitAttemptKey(SingleIssuer.Tenant, Credential, "life", 1));

    [Fact]
    public void DifferentCredentials_GetDifferentKeys()
        => Assert.NotEqual(Factory.AuthorizedGrantKey(SingleIssuer.Tenant, "code-a"), Factory.AuthorizedGrantKey(SingleIssuer.Tenant, "code-b"));

    private const string Credential = "SplxlOBeZQQYbYS6WxSbIA";

    // SHA-256 of Credential in UTF-8, lower-case hexadecimal, computed outside the code under test.
    private const string CredentialDigest = "a35b81a7d7927b70ec99270dd2362b88580a28574af812f2c02f56469579186f";
}
