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

    /// <summary>
    /// RFC 6750 §3.1: a request that carried no authentication information at all gets a bare
    /// challenge - realm only, no error attributes - on both the Bearer and the DPoP lines.
    /// </summary>
    [Fact]
    public void BuildChallenges_MissingAuthentication_EmitsBareChallenges()
    {
        var missingAuthentication = new MissingAuthenticationError("No access token provided");

        Assert.Equal(
            $"Bearer realm=\"{Realm}\"",
            WwwAuthenticateBuilder.BuildBearerChallenge(missingAuthentication, Realm));
        Assert.Equal(
            $"DPoP realm=\"{Realm}\", algs=\"RS256 ES256\"",
            WwwAuthenticateBuilder.BuildDPoPChallenge(missingAuthentication, Realm, DPoPAlgs));
    }

    [Fact]
    public void BuildBasicChallenge_WithRealm_EmitsRealmOnly()
    {
        // RFC 7617 defines no error attributes for the Basic scheme, so the challenge carries
        // only the realm - the error itself travels in the JSON body (RFC 6749 §5.2).
        var challenge = WwwAuthenticateBuilder.BuildBasicChallenge(Realm);

        Assert.Equal($"Basic realm=\"{Realm}\"", challenge);
    }

    [Fact]
    public void BuildBasicChallenge_NullRealm_EmitsBareScheme()
    {
        var challenge = WwwAuthenticateBuilder.BuildBasicChallenge(realm: null);

        Assert.Equal(TokenTypes.Basic, challenge);
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
        // failure - the Bearer line carries only the realm.
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
    public void BuildBearerChallenge_QuoteInDescription_BackslashEscaped()
    {
        // RFC 7235 §2.2 / RFC 9110 §5.6.4: inside a quoted-string each `"` MUST be
        // backslash-escaped. The builder preserves the original character rather than
        // substituting a different glyph so the on-wire value round-trips.
        var error = new OidcError(ErrorCodes.InvalidToken, "value with \"quotes\" inside");

        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm: null);

        Assert.Contains("error_description=\"value with \\\"quotes\\\" inside\"", challenge);
    }

    [Fact]
    public void BuildBearerChallenge_BackslashInDescription_DoubledForRfc7235()
    {
        // A literal backslash inside a quoted-string is itself the escape character,
        // so it MUST be doubled per RFC 7235 §2.2.
        var error = new OidcError(ErrorCodes.InvalidToken, @"value with \ inside");

        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm: null);

        Assert.Contains(@"error_description=""value with \\ inside""", challenge);
    }
}
