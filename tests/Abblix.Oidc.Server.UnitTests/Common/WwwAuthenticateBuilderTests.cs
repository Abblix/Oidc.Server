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
/// RFC 6750 section 3, DPoP-only emission per RFC 9449 section 7.1 (including the <c>algs</c>
/// attribute), the dual-scheme ordering rule (DPoP first, Bearer second when both are
/// advertised), and which of the two carries the error (RFC 9449 section 7.2).
/// </summary>
public class WwwAuthenticateBuilderTests
{
    private const string Realm = "auth.example.com";

    private static readonly OidcError InvalidToken = new(ErrorCodes.InvalidToken, "Token expired");
    private static readonly OidcError InvalidDPoPProof = new InvalidDPoPProofError("DPoP proof rejected");

    private static readonly OidcError InsufficientScope =
        new(ErrorCodes.InsufficientScope, "Needs openid") { RequiredScope = Scopes.OpenId };

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
    /// RFC 6750 section 3.1: a request that carried no authentication information at all gets a bare
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
        // only the realm - the error itself travels in the JSON body (RFC 6749 section 5.2).
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

    /// <summary>
    /// RFC 9449 section 7.2: "If the mechanism used to attempt authentication could be established unambiguously,
    /// then the corresponding challenge SHOULD be used to deliver error information". A DPoP failure puts the error
    /// on the DPoP challenge and leaves the Bearer one bare.
    /// </summary>
    [Fact]
    public void BuildChallenges_DPoPPresented_ErrorOnDPoPOnly()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidDPoPProof with { PresentedScheme = AccessTokenScheme.DPoP }, Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", error=\"{ErrorCodes.InvalidDPoPProof}\", " +
                $"error_description=\"DPoP proof rejected\", algs=\"RS256 ES256\"",
                $"Bearer realm=\"{Realm}\"",
            ],
            challenges);
    }

    /// <summary>
    /// RFC 9449 section 7.2, Figure 18: a request carrying <c>Authorization: Bearer INVALID_TOKEN</c> is answered
    /// with the error on the Bearer challenge, and the DPoP challenge keeps only its <c>algs</c>.
    /// </summary>
    [Fact]
    public void BuildChallenges_BearerPresented_ErrorOnBearerOnly()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidToken with { PresentedScheme = AccessTokenScheme.Bearer }, Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", algs=\"RS256 ES256\"",
                $"Bearer realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\"",
            ],
            challenges);
    }

    /// <summary>
    /// RFC 9449 section 7.2: where the mechanism cannot be established, "both Bearer and DPoP challenges MAY be used
    /// to deliver error information" (Figure 19).
    /// </summary>
    [Fact]
    public void BuildChallenges_SchemeNotEstablished_ErrorOnBoth()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(InvalidToken, Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\", " +
                "algs=\"RS256 ES256\"",
                $"Bearer realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\"",
            ],
            challenges);
    }

    /// <summary>
    /// RFC 9449 section 7.2: "If no authentication information has been included with the request, then the challenges
    /// SHOULD NOT include an error code or other error information", whatever scheme is recorded.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(AccessTokenScheme.Bearer)]
    [InlineData(AccessTokenScheme.DPoP)]
    public void BuildChallenges_MissingAuthentication_BareWhateverTheScheme(AccessTokenScheme? scheme)
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            new MissingAuthenticationError("No access token provided") { PresentedScheme = scheme },
            Realm, DPoPAlgs, advertiseBearer: true);

        Assert.Equal([$"DPoP realm=\"{Realm}\", algs=\"RS256 ES256\"", $"Bearer realm=\"{Realm}\""], challenges);
    }

    /// <summary>
    /// A sole challenge carries the error whichever scheme was used: with no algorithm to advertise DPoP is not
    /// offered, and the client that used it still learns why it was refused.
    /// </summary>
    [Fact]
    public void BuildChallenges_DPoPPresentedButNotOffered_ErrorOnTheSoleBearerChallenge()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidToken with { PresentedScheme = AccessTokenScheme.DPoP }, Realm, [], advertiseBearer: true);

        Assert.Equal(
            [$"Bearer realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\""],
            challenges);
    }

    /// <summary>
    /// The same for a resource advertising DPoP alone, answering a client that used Bearer.
    /// </summary>
    [Fact]
    public void BuildChallenges_BearerPresentedButNotOffered_ErrorOnTheSoleDPoPChallenge()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidToken with { PresentedScheme = AccessTokenScheme.Bearer }, Realm, DPoPAlgs, advertiseBearer: false);

        Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", error=\"{ErrorCodes.InvalidToken}\", error_description=\"Token expired\", " +
                "algs=\"RS256 ES256\"",
            ],
            challenges);
    }

    /// <summary>
    /// RFC 6750 section 3.1: insufficient_scope "MAY include the "scope" attribute with the scope necessary to access
    /// the protected resource", and RFC 9449 section 7.1 lets the DPoP challenge carry it "as defined in [RFC6750],
    /// Section 3". It rides the challenge carrying the error and only that one.
    /// </summary>
    [Fact]
    public void BuildChallenges_InsufficientScopeOverBearer_NamesTheScopeOnBearer()
        => Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", algs=\"RS256 ES256\"",
                $"Bearer realm=\"{Realm}\", error=\"{ErrorCodes.InsufficientScope}\", " +
                $"error_description=\"Needs openid\", scope=\"{Scopes.OpenId}\"",
            ],
            WwwAuthenticateBuilder.BuildChallenges(
                InsufficientScope with { PresentedScheme = AccessTokenScheme.Bearer },
                Realm, DPoPAlgs, advertiseBearer: true));

    /// <summary>
    /// The same refusal over DPoP names the scope on the DPoP challenge, before its <c>algs</c>.
    /// </summary>
    [Fact]
    public void BuildChallenges_InsufficientScopeOverDPoP_NamesTheScopeOnDPoP()
        => Assert.Equal(
            [
                $"DPoP realm=\"{Realm}\", error=\"{ErrorCodes.InsufficientScope}\", " +
                $"error_description=\"Needs openid\", scope=\"{Scopes.OpenId}\", algs=\"RS256 ES256\"",
                $"Bearer realm=\"{Realm}\"",
            ],
            WwwAuthenticateBuilder.BuildChallenges(
                InsufficientScope with { PresentedScheme = AccessTokenScheme.DPoP },
                Realm, DPoPAlgs, advertiseBearer: true));

    [Fact]
    public void BuildChallenges_BearerNotAdvertised_ReturnsDPoPOnly()
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(
            InvalidDPoPProof, Realm, DPoPAlgs, advertiseBearer: false);

        var only = Assert.Single(challenges);
        Assert.StartsWith("DPoP ", only);
    }

    [Fact]
    public void BuildBearerChallenge_QuoteInRealm_BackslashEscaped()
    {
        // RFC 7235 section 2.2 / RFC 9110 section 5.6.4: inside a quoted-string each `"` MUST be
        // backslash-escaped. The builder preserves the original character rather than
        // substituting a different glyph so the on-wire value round-trips. The realm is the host's
        // configuration and may hold one, while an error description never does
        var error = new OidcError(ErrorCodes.InvalidToken, "The token is expired");

        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm: "realm with \"quotes\" inside");

        Assert.Contains("realm=\"realm with \\\"quotes\\\" inside\"", challenge);
    }

    [Fact]
    public void BuildBearerChallenge_BackslashInRealm_DoubledForRfc7235()
    {
        // A literal backslash inside a quoted-string is itself the escape character,
        // so it MUST be doubled per RFC 7235 section 2.2.
        var error = new OidcError(ErrorCodes.InvalidToken, "The token is expired");

        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm: @"realm with \ inside");

        Assert.Contains(@"realm=""realm with \\ inside""", challenge);
    }
}
