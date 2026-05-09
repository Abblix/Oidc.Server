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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// Unit tests for <see cref="WwwAuthenticateBuilder"/>: covers Bearer-only emission per
/// RFC 6750 §3, DPoP-only emission per RFC 9449 §7.1 (including the <c>algs</c>
/// attribute), the dual-scheme ordering rule (DPoP first, Bearer second when both are
/// advertised), and the «Bearer line carries no error attributes when the failure was
/// DPoP-specific» exception that prevents the Bearer line from misrepresenting the
/// failure.
/// </summary>
public class WwwAuthenticateBuilderTests
{
    private const string Realm = "auth.example.com";

    private static readonly OidcError InvalidToken = new(ErrorCodes.InvalidToken, "Token expired");
    private static readonly OidcError InvalidDPoPProof = new InvalidDPoPProofError("DPoP proof rejected");

    private static readonly string[] DPoPAlgs = ["RS256", "ES256"];

    [Fact]
    public void BuildBearerChallenge_WithError_EmitsRealmAndErrorAttributes()
    {
        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(InvalidToken, Realm);

        Assert.Equal(
            $"Bearer realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\"",
            challenge);
    }

    [Fact]
    public void BuildBearerChallenge_WithoutError_EmitsRealmOnly()
    {
        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(InvalidToken, Realm, includeError: false);

        Assert.Equal($"Bearer realm=\"{Realm}\"", challenge);
    }

    [Fact]
    public void BuildBearerChallenge_NullRealm_OmitsRealmAttribute()
    {
        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(InvalidToken, realm: null);

        Assert.Equal(
            $"Bearer error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\"",
            challenge);
    }

    [Fact]
    public void BuildDPoPChallenge_EmitsAllAttributesIncludingSpaceSeparatedAlgs()
    {
        var challenge = WwwAuthenticateBuilder.BuildDPoPChallenge(InvalidDPoPProof, Realm, DPoPAlgs);

        Assert.Equal(
            $"DPoP realm=\"{Realm}\", error=\"{ErrorCodes.InvalidDPoPProof}\", error_description=\"DPoP proof rejected\", algs=\"RS256 ES256\"",
            challenge);
    }

    [Fact]
    public void BuildChallenges_DualScheme_DPoPFirstBearerSecond()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidDPoPProof, Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal(2, challenges.Count);
        Assert.StartsWith("DPoP ", challenges[0]);
        Assert.StartsWith("Bearer ", challenges[1]);
    }

    [Fact]
    public void BuildChallenges_DualScheme_BearerCarriesNoErrorAttributes()
    {
        // RFC 9449 §7.1: «the Bearer scheme didn't fail; the client used the DPoP scheme».
        // Attaching error="invalid_dpop_proof" to the Bearer line would misrepresent the
        // failure — the Bearer line carries only the realm.
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidDPoPProof, Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal($"Bearer realm=\"{Realm}\"", challenges[1]);
    }

    [Fact]
    public void BuildChallenges_BearerNotAdvertised_ReturnsDPoPOnly()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidDPoPProof, Realm, DPoPAlgs, advertiseBearer: false);

        var only = Assert.Single(challenges);
        Assert.StartsWith("DPoP ", only);
    }

    [Fact]
    public void BuildBearerChallenge_QuoteInDescription_ReplacedWithSingleQuote()
    {
        // Quoted-string values cannot contain bare double quotes (RFC 7235 §2.1). The
        // builder substitutes them with single quotes to keep the value parseable without
        // escaping logic at every call site.
        var error = new OidcError(ErrorCodes.InvalidToken, "value with \"quotes\" inside");

        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm: null);

        Assert.Contains("error_description=\"value with 'quotes' inside\"", challenge);
        Assert.DoesNotContain("\"value with \"", challenge);
    }
}
