// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

    /// <summary>
    /// RFC 9449 Section 7.1, Figure 15, verbatim: "HTTP 401 Response to a Protected Resource Request
    /// without Authentication" prints <c>WWW-Authenticate: DPoP algs="ES256 PS256"</c>.
    /// </summary>
    /// <remarks>
    /// The point of the figure is the SEPARATOR. With no realm, <c>algs</c> is the challenge's first
    /// parameter and follows the scheme with a space; a comma there is not a challenge under RFC 9110's
    /// grammar, and a parser reads the scheme as parameterless and then chokes on the rest.
    /// <para>
    /// The rest of this class guards that separator well - breaking it alone kills twelve of these
    /// fifteen rows, most of them because the realm is what comes first. What none of them can see is a
    /// parameter that BYPASSES the builder, which is what <c>algs</c> did: these three rows are the only
    /// thing in the solution that catches it, measured.
    /// </para>
    /// </remarks>
    [Fact]
    public void BuildDPoPChallenge_WithoutRealm_MatchesTheSpecificationFigure()
        => Assert.Equal(
            "DPoP algs=\"ES256 PS256\"",
            WwwAuthenticateBuilder.BuildDPoPChallenge(
                new MissingAuthenticationError("No access token provided"),
                realm: null,
                ["ES256", "PS256"]));

    /// <summary>
    /// An <c>algs</c> value carrying a quotation mark has to be escaped like any other parameter, or it
    /// ends the quoted string early and the rest of the header is read as something else.
    /// </summary>
    /// <remarks>
    /// The parameter is an unconstrained sequence on a public method of a published package, so what a
    /// caller puts in it is not this library's choice.
    /// </remarks>
    [Fact]
    public void BuildDPoPChallenge_AlgsCarryingSpecials_AreEscaped()
        => Assert.Equal(
            "DPoP realm=\"r\", algs=\"a\\\"b\"",
            WwwAuthenticateBuilder.BuildDPoPChallenge(
                new MissingAuthenticationError("No access token provided"), "r", ["a\"b"]));

    /// <summary>
    /// No algorithms leaves the parameter out rather than emitting <c>algs=""</c>, which advertises a
    /// scheme that accepts nothing.
    /// </summary>
    [Fact]
    public void BuildDPoPChallenge_NoAlgs_OmitsTheParameter()
        => Assert.Equal(
            "DPoP realm=\"r\"",
            WwwAuthenticateBuilder.BuildDPoPChallenge(
                new MissingAuthenticationError("No access token provided"), "r", []));

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
