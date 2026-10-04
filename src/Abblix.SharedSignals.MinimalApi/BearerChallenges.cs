// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The refusals of the management surface that explain themselves in a <c>WWW-Authenticate</c> line.
/// </summary>
internal static class BearerChallenges
{
    /// <summary>
    /// A required parameter names nothing, so the request cannot be acted on. That covers a parameter
    /// left out and one sent empty alike, and RFC 6750 Section 3.1 puts both in the same bucket:
    /// <c>invalid_request</c> is "The request is missing a required parameter, includes an unsupported
    /// parameter or parameter value ... The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code."
    /// </summary>
    /// <remarks>
    /// The header is a MAY here, unlike the 401 below. Section 3 makes <c>WWW-Authenticate</c> mandatory
    /// when the request "does not include authentication credentials or does not contain an access token
    /// that enables access", and adds that a server "MAY include it in response to other conditions as
    /// well". This is one of those others: the receiver was identified and its token is not in question,
    /// only a protocol parameter names nothing. The header carries it anyway, because that is where Section
    /// 3.1's vocabulary lives and it is what the 401 and 403 on these same routes already use, so a
    /// receiver has one place to read a refusal from.
    /// <para>
    /// This answers only where the parameter is REQUIRED.
    /// <see cref="StreamManagementHandlers.GetStreamsAsync"/> takes the same query parameter and lists
    /// every stream when it names nothing, so an unnamed stream there is an answer rather than an error.
    /// Both routes read "named" the same way; they differ in what it means.
    /// </para>
    /// </remarks>
    internal static IResult MissingRequiredParameter(HttpContext http, string parameterName)
    {
        var issuer = http.RequestServices.GetService<ITransmitterIdentity>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status400BadRequest,
            WwwAuthenticate.Challenge(
                BearerScheme,
                ("realm", issuer),
                ("error", "invalid_request"),
                // Says the parameter NAMES NOTHING rather than that it is missing, because the empty
                // value reaches here too and the receiver sent it - a developer told the parameter is
                // missing goes looking for where their client drops it, and it does not drop it.
                ("error_description",
                    $"The required parameter {parameterName} names nothing.")));
    }

    /// <summary>
    /// The answer to a management request that named no receiver: 401 with a bare Bearer challenge.
    /// </summary>
    /// <remarks>
    /// Bare, and deliberately so. This refusal has one cause - nothing identified the caller - which is
    /// what RFC 6750 Section 3.1 describes as a request that "lacks any authentication information", and
    /// for which it says the resource server "SHOULD NOT include an error code or other error
    /// information". A caller that presented nothing has nothing to correct. It is not the only refusal
    /// on this surface: a caller that IS identified but lacks the scope gets 403 from
    /// <see cref="ScopeRequirement.EnforceScopeAsync"/>, which runs first, and that ordering is deliberate.
    /// <para>
    /// That section defines three codes and this method answers none of them. Validating the token
    /// belongs to the host: this package never sees one, it reads whatever identity the host's
    /// authentication left behind, through <see cref="SharedSignalsEndpointOptions.ReceiverIdSelector"/>.
    /// It answers <c>invalid_token</c> only where that identity's credentials do not come from the issuer
    /// the transmitter takes its receivers from, in <see cref="ForeignIssuer"/>. <c>insufficient_scope</c>
    /// IS emitted by this package, from <see cref="ScopeRequirement.EnforceScopeAsync"/>, once the host
    /// supplies the granted scopes.
    /// </para>
    /// <para>
    /// The third, <c>invalid_request</c> with 400, is also decided here rather than by the host, and is
    /// emitted by <see cref="MissingRequiredParameter"/>.
    /// </para>
    /// <para>
    /// The realm is the transmitter's issuer, which is the one name a receiver already holds for this
    /// protection space and the one it used to find these endpoints.
    /// </para>
    /// </remarks>
    internal static IResult Unauthenticated(HttpContext http)
    {
        var issuer = http.RequestServices.GetService<ITransmitterIdentity>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status401Unauthorized, WwwAuthenticate.Challenge(BearerScheme, issuer));
    }

    /// <summary>
    /// The answer to a receiver whose credentials do not come from the issuer this transmitter takes its
    /// receivers from: 401 with <c>invalid_token</c>.
    /// </summary>
    /// <remarks>
    /// RFC 6750 Section 3.1 gives that code to an access token that is "expired, revoked, malformed, or
    /// invalid for other reasons", and a token from another issuer, or naming none, is invalid here for such a
    /// reason. The code lets the receiver ask for a new token and retry; the description, which that section
    /// meant for developers, is what says a token from the same issuer will be refused again.
    /// </remarks>
    internal static IResult ForeignIssuer(HttpContext http)
    {
        var issuer = http.RequestServices.GetService<ITransmitterIdentity>()?.Issuer;
        return new ChallengeResult(
            StatusCodes.Status401Unauthorized,
            WwwAuthenticate.Challenge(
                BearerScheme,
                ("realm", issuer),
                ("error", "invalid_token"),
                ("error_description",
                    "The access token does not come from the issuer this transmitter takes its receivers from.")));
    }

    /// <summary>
    /// The scheme this surface advertises. Not a claim about how the host authenticates - it is what the
    /// CAEP Interoperability Profile Section 2.7.2 obliges a transmitter to accept: "MUST accept access
    /// tokens in the HTTP header as in Section 2.1 of OAuth 2.0 Bearer Token Usage [RFC6750]". So it is
    /// the scheme a receiver reading this challenge is prepared to act on.
    /// <para>
    /// Section 2.4.3 is the neighbouring requirement and does NOT carry this: it says a receiver "MUST
    /// use OAuth 2.0 [RFC6749]", which is the framework and fixes no token type.
    /// </para>
    /// </summary>
    internal const string BearerScheme = "Bearer";
}
