// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.UnitTests.ActionResults;

/// <summary>
/// The HTTP shape this adapter gives a protocol error: which status code, which
/// <c>WWW-Authenticate</c> challenge, and whether the error travels in the body or only on the header
/// (RFC 6750 section 3, RFC 6749 section 5.2, RFC 9449 sections 7.1 and 8).
/// </summary>
/// <remarks>
/// The twin of the Minimal API suite's <c>OidcResultsErrorShapeTests</c>, case for case and assertion for
/// assertion. The two adapters are meant to answer identically, so the cases are deliberately not divided
/// between them: what a difference in coverage hides is precisely the arm where one adapter answers 403 and the
/// other 401.
///
/// These arms are hard to reach end to end - a live <c>insufficient_scope</c> or a nonce challenge needs a
/// deployment configured to produce one - while the mapping itself is a pure function of the error and the
/// fallback status. So it is tested here directly, and executed rather than inspected, because the header a
/// client keys on is applied by a decorator during execution.
/// </remarks>
public class ActionResultErrorShapeTests
{
    private const string Realm = "https://auth.example.com";
    private static readonly string[] DPoPAlgs = [SigningAlgorithms.RS256, SigningAlgorithms.ES256];

    private static string Challenge(ActionResultRunner.Response response)
        => response.Headers[HeaderNames.WWWAuthenticate].ToString();

    /// <summary>
    /// RFC 6750 section 3: a bad bearer token is answered on the challenge header, not in a body - the client
    /// reads <c>error</c> off <c>WWW-Authenticate</c>, so a JSON body would be a second, redundant statement.
    /// </summary>
    [Fact]
    public async Task Invalid_token_answers_401_on_the_header_with_no_body()
    {
        var error = new OidcError(ErrorCodes.InvalidToken, "The access token expired");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.Contains(TokenTypes.Bearer, Challenge(response));
        Assert.Contains(ErrorCodes.InvalidToken, Challenge(response));
        Assert.Empty(response.Body);
    }

    /// <summary>
    /// RFC 6750 section 3.1: the token is valid, so 401 would tell the client to re-authenticate for nothing.
    /// The scope it lacks is a 403.
    /// </summary>
    [Fact]
    public async Task Insufficient_scope_answers_403_on_the_header_with_no_body()
    {
        var error = new OidcError(ErrorCodes.InsufficientScope, "The token lacks the profile scope");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm));

        Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
        Assert.Contains(ErrorCodes.InsufficientScope, Challenge(response));
        Assert.Empty(response.Body);
    }

    /// <summary>
    /// RFC 6749 section 5.2: a client-authentication failure is a 401 with a Basic challenge, and the error stays
    /// in the body because RFC 7617 gives the Basic scheme no error attributes to carry it on.
    /// </summary>
    [Fact]
    public async Task Invalid_client_answers_401_with_a_basic_challenge_and_the_error_in_the_body()
    {
        var error = new OidcError(ErrorCodes.InvalidClient, "Client authentication failed");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.Contains(TokenTypes.Basic, Challenge(response));
        Assert.DoesNotContain(ErrorCodes.InvalidClient, Challenge(response));
        Assert.Contains(ErrorCodes.InvalidClient, response.Body);
    }

    /// <summary>
    /// Every other error takes the status the endpoint asked for and states itself in the body. The three
    /// fallbacks are separate arms in the mapping, so each is driven: a 400 the token endpoint asks for, a 401
    /// asked for without the client-authentication semantics, and anything else.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidGrant, StatusCodes.Status401Unauthorized)]
    [InlineData(ErrorCodes.ServerError, StatusCodes.Status500InternalServerError)]
    public async Task An_ordinary_error_takes_the_requested_status_and_states_itself_in_the_body(
        string errorCode, int fallbackStatusCode)
    {
        var error = new OidcError(errorCode, "Something the client must read");

        var response = await ActionResultRunner.RunAsync(error.Format(fallbackStatusCode, Realm));

        Assert.Equal(fallbackStatusCode, response.StatusCode);
        Assert.Contains(errorCode, response.Body);
        Assert.Contains("Something the client must read", response.Body);
    }

    /// <summary>
    /// RFC 9449 section 7.1: a rejected proof is answered under the DPoP scheme, advertising the algorithms the
    /// server accepts, so the client knows what to sign the next proof with.
    /// </summary>
    [Fact]
    public async Task A_rejected_dpop_proof_answers_401_under_the_dpop_scheme()
    {
        var error = new InvalidDPoPProofError("The proof signature did not verify");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm, DPoPAlgs, advertiseBearer: false));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.Contains(TokenTypes.DPoP, Challenge(response));
        Assert.Contains(SigningAlgorithms.ES256, Challenge(response));
        Assert.DoesNotContain(TokenTypes.Bearer, Challenge(response));
        Assert.Empty(response.Body);
    }

    /// <summary>
    /// RFC 9449 section 8: the nonce the client must echo travels on its own header. Without it the retry
    /// carries the same stale nonce and fails again, so this is the one arm where a missing header costs the
    /// client the whole exchange.
    /// </summary>
    [Fact]
    public async Task A_nonce_challenge_carries_the_fresh_nonce_on_its_own_header()
    {
        var error = new UseDPoPNonceError("nonce-value-42");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm, DPoPAlgs, advertiseBearer: true));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        Assert.Equal("nonce-value-42", response.Headers[HttpRequestHeaders.DPoPNonce].ToString());
        Assert.Contains(ErrorCodes.UseDPoPNonce, Challenge(response));
    }

    /// <summary>
    /// RFC 9449 section 7.1: when both schemes are advertised the DPoP line comes first, and the Bearer line
    /// carries only the realm - the Bearer scheme did not fail, so attaching the DPoP error to it would name the
    /// wrong culprit.
    /// </summary>
    [Fact]
    public async Task Advertising_both_schemes_puts_dpop_first_and_leaves_the_bearer_line_bare()
    {
        var error = new InvalidDPoPProofError("The proof is missing the htm claim");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm, DPoPAlgs, advertiseBearer: true));

        var challenges = response.Headers[HeaderNames.WWWAuthenticate];

        Assert.Equal(2, challenges.Count);
        Assert.StartsWith(TokenTypes.DPoP, challenges[0]);
        Assert.StartsWith(TokenTypes.Bearer, challenges[1]);
        Assert.DoesNotContain(ErrorCodes.InvalidDPoPProof, challenges[1]);
    }

    /// <summary>
    /// The DPoP-aware overload keeps the same status mapping as the plain one for errors that are not about the
    /// proof: a bad token is still a 401 answered on the header, and a missing scope is still a 403.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidToken, StatusCodes.Status401Unauthorized)]
    [InlineData(ErrorCodes.InsufficientScope, StatusCodes.Status403Forbidden)]
    public async Task A_token_failure_under_dpop_keeps_the_status_the_bearer_mapping_gives_it(
        string errorCode, int expectedStatusCode)
    {
        var error = new OidcError(errorCode, "Refused");

        var response = await ActionResultRunner.RunAsync(
            error.Format(StatusCodes.Status400BadRequest, Realm, DPoPAlgs, advertiseBearer: false));

        Assert.Equal(expectedStatusCode, response.StatusCode);
        Assert.Empty(response.Body);
    }

    /// <summary>
    /// And an ordinary error under the DPoP overload still takes the requested status with a body, so a client
    /// that sent a proof reads the same envelope as one that did not.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidGrant, StatusCodes.Status401Unauthorized)]
    [InlineData(ErrorCodes.ServerError, StatusCodes.Status500InternalServerError)]
    public async Task An_ordinary_error_under_dpop_takes_the_requested_status_with_a_body(
        string errorCode, int fallbackStatusCode)
    {
        var error = new OidcError(errorCode, "Something the client must read");

        var response = await ActionResultRunner.RunAsync(
            error.Format(fallbackStatusCode, Realm, DPoPAlgs, advertiseBearer: false));

        Assert.Equal(fallbackStatusCode, response.StatusCode);
        Assert.Contains(errorCode, response.Body);
        Assert.Contains(TokenTypes.DPoP, Challenge(response));
    }
}
