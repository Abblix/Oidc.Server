// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
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

    [Theory]
    [InlineData(RevocationScope.Subject, "Abblix.Oidc.Server:Revoked:subject:user_42")]
    [InlineData(RevocationScope.Session, "Abblix.Oidc.Server:Revoked:session:user_42")]
    public void RevocationCutoffKey_HasTheNameLiveRecordsAreHeldUnder(RevocationScope scope, string expected)
    {
        Assert.Equal(expected, Factory.RevocationCutoffKey(scope, "user_42"));
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
            Factory.DeviceAuthorizationRequestKey(awkward),
            Factory.DeviceAuthorizationNextPollKey(plain));

        Assert.NotEqual(
            Factory.BackChannelAuthenticationRequestKey(awkward),
            Factory.BackChannelAuthenticationNextPollKey(plain));
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
            Factory.DeviceAuthorizationRequestKey("Reuse:code_challenge:a-hash"),
            Factory.AuthorizationValueReuseKey("Device", "code_challenge", "a-hash"));

        Assert.NotEqual(
            Factory.BackChannelAuthenticationRequestKey("Reuse:code_challenge:a-hash"),
            Factory.AuthorizationValueReuseKey("CIBA", "code_challenge", "a-hash"));
    }

    /// <summary>
    /// The record that a flow ended is never held under the key of a stored request, so writing it cannot replace
    /// a request still in flight.
    /// </summary>
    [Fact]
    public void ConsumedRequestUriKey_IsNeverSpelledLikeRequestKey()
    {
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:pushed");

        Assert.NotEqual(Factory.AuthorizationRequestKey(requestUri), Factory.ConsumedRequestUriKey(requestUri));
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
            Factory.AddressRateLimitAttemptKey("a1", 2, 3),
            Factory.AddressRateLimitAttemptKey("a", 12, 3),
            Factory.AddressRateLimitAttemptKey("a:1", 2, 3),
            Factory.AddressRateLimitAttemptKey("a", 1, 23),
            Factory.AddressRateLimitAttemptKey("::1", 5, 1),
            Factory.AddressRateLimitAttemptKey("::1:5", 1, 1),
            Factory.AddressRateLimitAttemptKey("x:Attempt:1", 2, 3),
            Factory.AddressRateLimitAttemptKey("x", 1, 2),
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
            Factory.DeviceAuthorizationRequestKey(identifier),
            Factory.DeviceAuthorizationNextPollKey(identifier),
            Factory.BackChannelAuthenticationRequestKey(identifier),
            Factory.BackChannelAuthenticationNextPollKey(identifier),
            Factory.DeviceAuthorizationUserCodeKey(identifier),
            Factory.UserCodeRateLimitAttemptKey(identifier, life: "a-life", attempt: 1),
            Factory.AddressRateLimitAttemptKey(identifier, 1, 1),
            Factory.AuthorizedGrantKey(identifier),
            Factory.JsonWebTokenStatusKey(identifier),
            Factory.AuthorizationValueReuseKey(identifier, "code_challenge", "a-hash"),
            Factory.SessionClientsGenerationKey(identifier),
            Factory.SessionClientKey(identifier, identifier, 1),
            Factory.SessionClientMarkerKey(identifier, identifier, identifier),
            Factory.SessionClientsRenewalKey(identifier, identifier),
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

        var keys = scopes.Select(scope => Factory.RevocationCutoffKey(scope, "user_42")).ToArray();

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

        Assert.Throws<ArgumentOutOfRangeException>(() => Factory.RevocationCutoffKey(unknown, "user_42"));
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
            Factory.AuthorizedGrantKey(credential),
            Factory.BackChannelAuthenticationRequestKey(credential),
            Factory.BackChannelAuthenticationNextPollKey(credential),
            Factory.DeviceAuthorizationRequestKey(credential),
            Factory.DeviceAuthorizationNextPollKey(credential),
            Factory.DeviceAuthorizationUserCodeKey(credential),
            Factory.UserCodeRateLimitAttemptKey(credential, "life", 1),
            Factory.UserCodeRateLimitGenerationKey(credential),
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
            nameof(IEntityStorageKeyFactory.AuthorizedGrantKey) => Factory.AuthorizedGrantKey(Credential),
            nameof(IEntityStorageKeyFactory.BackChannelAuthenticationRequestKey) => Factory.BackChannelAuthenticationRequestKey(Credential),
            nameof(IEntityStorageKeyFactory.BackChannelAuthenticationNextPollKey) => Factory.BackChannelAuthenticationNextPollKey(Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationRequestKey) => Factory.DeviceAuthorizationRequestKey(Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationNextPollKey) => Factory.DeviceAuthorizationNextPollKey(Credential),
            nameof(IEntityStorageKeyFactory.DeviceAuthorizationUserCodeKey) => Factory.DeviceAuthorizationUserCodeKey(Credential),
            nameof(IEntityStorageKeyFactory.UserCodeRateLimitGenerationKey) => Factory.UserCodeRateLimitGenerationKey(Credential),
            _ => throw new ArgumentOutOfRangeException(nameof(method), method, "No such key method in this test"),
        };

        Assert.Equal(expected, key);
    }

    [Fact]
    public void AnAttemptKeyOfAUserCode_IsItsDigestUnderTheEntryName()
        => Assert.Equal(
            "Abblix.Oidc.Server:RateLimit:UserCode:" + CredentialDigest + ":life:Attempt:1",
            Factory.UserCodeRateLimitAttemptKey(Credential, "life", 1));

    [Fact]
    public void DifferentCredentials_GetDifferentKeys()
        => Assert.NotEqual(Factory.AuthorizedGrantKey("code-a"), Factory.AuthorizedGrantKey("code-b"));

    private const string Credential = "SplxlOBeZQQYbYS6WxSbIA";

    // SHA-256 of Credential in UTF-8, lower-case hexadecimal, computed outside the code under test.
    private const string CredentialDigest = "a35b81a7d7927b70ec99270dd2362b88580a28574af812f2c02f56469579186f";
}
