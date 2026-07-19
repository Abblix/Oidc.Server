// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// Unit tests for <see cref="SubjectTypeConverter"/> verifying pairwise subject derivation per
/// OIDC Core §8.1, in particular the sector identifier fallback chain for statically configured
/// clients without an explicit sector identifier.
/// </summary>
public class SubjectTypeConverterTests
{
    private const string Subject = "user_123";

    // Test-only salt: 32 zero bytes, base64-encoded.
    private static readonly string TestSalt = Convert.ToBase64String(new byte[32]);

    private static SubjectTypeConverter CreateConverter() => new(new PairwiseSubjectSettings { Salt = TestSalt });

    private static ClientInfo CreatePairwiseClient(
        string clientId,
        string? sectorIdentifier = null,
        Uri[]? redirectUris = null) => new(clientId)
    {
        SubjectType = SubjectTypes.Pairwise,
        SectorIdentifier = sectorIdentifier,
        RedirectUris = redirectUris ?? [],
    };

    /// <summary>
    /// OIDC Core §8.1: without an explicit sector identifier the sector is the host component of
    /// the registered redirect_uri - two statically configured clients of the same sector must
    /// derive the same pairwise subject. The previous client_id fallback broke exactly this.
    /// </summary>
    [Fact]
    public void Convert_NoSectorIdentifier_DerivesSectorFromRedirectUriHost()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb1")]);
        var clientB = CreatePairwiseClient("client-b", redirectUris: [new Uri("https://app.example.com/cb2")]);

        Assert.Equal(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// An explicit sector identifier takes precedence over the redirect_uri host fallback.
    /// </summary>
    [Fact]
    public void Convert_ExplicitSectorIdentifier_OverridesRedirectUriHost()
    {
        var converter = CreateConverter();
        var withSector = CreatePairwiseClient(
            "client-a", sectorIdentifier: "sector.example.com",
            redirectUris: [new Uri("https://app.example.com/cb")]);
        var hostDerived = CreatePairwiseClient(
            "client-b", redirectUris: [new Uri("https://app.example.com/cb")]);

        Assert.NotEqual(converter.Convert(Subject, withSector), converter.Convert(Subject, hostDerived));
    }

    /// <summary>
    /// Custom-scheme redirect URIs of native clients (RFC 8252 §7.1) carry no meaningful host:
    /// the single-slash form parses with an empty Host, and the authority form puts an arbitrary
    /// path-like segment there - either would merge unrelated clients into one shared sector,
    /// giving them identical pairwise subjects and defeating the isolation pairwise subject
    /// types exist to provide (OIDC Core §8.1). The client_id fallback applies instead.
    /// </summary>
    [Theory]
    [InlineData("com.example.one:/oauth2redirect", "com.example.two:/oauth2redirect")]
    [InlineData("app-one://callback", "app-two://callback")]
    public void Convert_CustomSchemeRedirectUri_FallsBackToClientId(string redirectUriA, string redirectUriB)
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", redirectUris: [new Uri(redirectUriA)]);
        var clientB = CreatePairwiseClient("client-b", redirectUris: [new Uri(redirectUriB)]);

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// Different sectors must produce unlinkable identifiers for the same subject - the core
    /// privacy property of pairwise subject types.
    /// </summary>
    [Fact]
    public void Convert_DifferentSectors_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var sectorOne = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://one.example.com/cb")]);
        var sectorTwo = CreatePairwiseClient("client-b", redirectUris: [new Uri("https://two.example.com/cb")]);

        Assert.NotEqual(converter.Convert(Subject, sectorOne), converter.Convert(Subject, sectorTwo));
    }

    /// <summary>
    /// A pairwise subject is stable: the same (subject, sector) always seals to the same value, so a client sees a
    /// consistent identifier for the user across logins - the core stability guarantee of OIDC Core §8.1.
    /// </summary>
    [Fact]
    public void Convert_SameSubjectAndClient_IsDeterministic()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb")]);

        Assert.Equal(converter.Convert(Subject, client), converter.Convert(Subject, client));
    }

    /// <summary>
    /// The pairwise identifier is reversible: Recover opens it back to the exact original subject, and the sealed
    /// value is not the bare subject - this is what lets the server carry the pseudonym in tokens yet still resolve
    /// the real user.
    /// </summary>
    [Fact]
    public void Recover_AfterConvert_ReturnsOriginalSubject()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", redirectUris: [new Uri("https://app.example.com/cb")]);

        var pairwise = converter.Convert(Subject, client);

        Assert.NotEqual(Subject, pairwise);
        Assert.Equal(Subject, converter.Recover(pairwise, client));
    }

    /// <summary>
    /// Sector, not client id, determines the identifier: two distinct clients sharing an explicit sector_identifier
    /// seal the same subject to the same value, so a sector's back-ends see one consistent identifier (OIDC Core
    /// §8.1).
    /// </summary>
    [Fact]
    public void Convert_SameExplicitSectorIdentifier_DifferentClients_ProduceSameSubject()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var clientB = CreatePairwiseClient("client-b", sectorIdentifier: "sector.example.com");

        Assert.Equal(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// Different sectors stay unlinkable: the same subject under two distinct explicit sector_identifiers seals to
    /// different values, the privacy property pairwise subject types exist to provide.
    /// </summary>
    [Fact]
    public void Convert_DifferentExplicitSectorIdentifiers_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a", sectorIdentifier: "one.example.com");
        var clientB = CreatePairwiseClient("client-b", sectorIdentifier: "two.example.com");

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// A pairwise identifier sealed for one sector cannot be opened under another: the sector is bound as associated
    /// data, so Recover under the wrong client's sector returns null instead of a wrong or forged subject, letting
    /// the caller reject the token.
    /// </summary>
    [Fact]
    public void Recover_UnderDifferentSector_ReturnsNull()
    {
        var converter = CreateConverter();
        var sealingClient = CreatePairwiseClient("client-a", sectorIdentifier: "one.example.com");
        var otherSectorClient = CreatePairwiseClient("client-b", sectorIdentifier: "two.example.com");

        var pairwise = converter.Convert(Subject, sealingClient);

        Assert.Null(converter.Recover(pairwise, otherSectorClient));
    }

    /// <summary>
    /// A public client's subject is not transformed: Convert returns it unchanged, so the client sees the real
    /// subject (OIDC Core §8, the public subject type).
    /// </summary>
    [Fact]
    public void Convert_PublicClient_ReturnsSubjectUnchanged()
    {
        var converter = CreateConverter();
        var client = new ClientInfo("client-pub") { SubjectType = SubjectTypes.Public };

        Assert.Equal(Subject, converter.Convert(Subject, client));
    }

    /// <summary>
    /// A public client's subject passes through on the way back too: Recover returns it unchanged, since a public
    /// subject is never sealed.
    /// </summary>
    [Fact]
    public void Recover_PublicClient_ReturnsSubjectUnchanged()
    {
        var converter = CreateConverter();
        var client = new ClientInfo("client-pub") { SubjectType = SubjectTypes.Public };

        Assert.Equal(Subject, converter.Recover(Subject, client));
    }

    /// <summary>
    /// The subject is part of the seal, not ignored: two different users in the same sector get different pairwise
    /// identifiers, so a sector cannot conflate two accounts into one.
    /// </summary>
    [Fact]
    public void Convert_DifferentSubjects_SameSector_ProduceDifferentSubjects()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.NotEqual(converter.Convert("user-one", client), converter.Convert("user-two", client));
    }

    /// <summary>
    /// Pairwise identifiers require configuration: a converter built without pairwise settings fails loudly when a
    /// pairwise client asks to seal a subject, rather than silently leaking the real subject.
    /// </summary>
    [Fact]
    public void Convert_PairwiseWithoutSettings_Throws()
    {
        var converter = new SubjectTypeConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.Throws<InvalidOperationException>(() => converter.Convert(Subject, client));
    }

    /// <summary>
    /// The same fail-loud guard covers the reverse direction: a converter without pairwise settings cannot open a
    /// pairwise identifier and throws instead of returning a wrong subject.
    /// </summary>
    [Fact]
    public void Recover_PairwiseWithoutSettings_Throws()
    {
        var configured = CreateConverter();
        var unconfigured = new SubjectTypeConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var pairwise = configured.Convert(Subject, client);

        Assert.Throws<InvalidOperationException>(() => unconfigured.Recover(pairwise, client));
    }

    /// <summary>
    /// The identifier is stable across converter instances sharing the salt, not tied to one process: a pseudonym
    /// sealed by one instance is reproduced and opened by another, so pairwise identifiers survive a restart and work
    /// on a stateless server farm.
    /// </summary>
    [Fact]
    public void ConvertAndRecover_AreStableAcrossInstances_WithSameSalt()
    {
        var instanceA = CreateConverter();
        var instanceB = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        var sealedByA = instanceA.Convert(Subject, client);

        Assert.Equal(sealedByA, instanceB.Convert(Subject, client));
        Assert.Equal(Subject, instanceB.Recover(sealedByA, client));
    }

    /// <summary>
    /// A syntactically invalid pseudonym (not even valid base64url) returns null rather than being mis-parsed into a
    /// bogus subject, letting the caller reject the token.
    /// </summary>
    [Fact]
    public void Recover_MalformedPseudonym_ReturnsNull()
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");

        Assert.Null(converter.Recover("not valid base64url!!", client));
    }

    /// <summary>
    /// The last-resort sector fallback is the client id: two clients with neither a sector_identifier nor any
    /// redirect URIs (for example client_credentials-only clients) stay isolated, each sealing the same subject to a
    /// different value.
    /// </summary>
    [Fact]
    public void Convert_NoSectorIdentifierNoRedirectUris_FallsBackToClientId()
    {
        var converter = CreateConverter();
        var clientA = CreatePairwiseClient("client-a");
        var clientB = CreatePairwiseClient("client-b");

        Assert.NotEqual(converter.Convert(Subject, clientA), converter.Convert(Subject, clientB));
    }

    /// <summary>
    /// The pairwise identifier stays compact: it is the base64url of an AES key wrap of the subject, so its length
    /// is a small, bounded function of the subject length - 16 wrapped bytes (22 base64url chars) for a subject up
    /// to one 8-byte semiblock, then 8 more wrapped bytes per further semiblock. This pins the size contract so an
    /// unexpected growth (which would inflate every token's sub) is caught by a regression.
    /// </summary>
    [Theory]
    [InlineData(1, 22)]
    [InlineData(8, 22)]
    [InlineData(9, 32)]
    [InlineData(16, 32)]
    [InlineData(17, 43)]
    [InlineData(36, 64)]
    public void Convert_PairwiseIdentifierLength_IsBoundedBySubjectLength(int subjectByteLength, int expectedLength)
    {
        var converter = CreateConverter();
        var client = CreatePairwiseClient("client-a", sectorIdentifier: "sector.example.com");
        var subject = new string('a', subjectByteLength); // ASCII, one byte per character

        var pairwise = converter.Convert(subject, client);

        Assert.Equal(expectedLength, pairwise.Length);
    }
}
