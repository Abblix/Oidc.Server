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
using Abblix.Oidc.Server.Features.UserInfo;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserInfo;

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
    /// the registered redirect_uri — two statically configured clients of the same sector must
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
    /// path-like segment there — either would merge unrelated clients into one shared sector,
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
    /// Different sectors must produce unlinkable identifiers for the same subject — the core
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
}
