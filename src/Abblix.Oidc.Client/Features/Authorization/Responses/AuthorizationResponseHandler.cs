// Abblix OIDC Client Library
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

using System.Globalization;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.IdentityTokens;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Runs an authorization response through parsing, issuer verification and state consumption, in the
/// one order that makes each step safe.
/// </summary>
/// <param name="parser">Takes the response apart without judging it.</param>
/// <param name="stateConsumer">Matches the response to a held login and consumes it, once.</param>
/// <param name="issuerValidator">Confirms the response came from the provider the login was started with.</param>
/// <param name="identityTokenValidator">Validates an ID Token that arrived from the authorization endpoint.</param>
/// <param name="requestOptions">Names the flow this client asked for, which the response must match.</param>
internal sealed class AuthorizationResponseHandler(
    IAuthorizationResponseParser parser,
    IAuthorizationStateConsumer stateConsumer,
    IResponseIssuerValidator issuerValidator,
    IIdentityTokenValidator identityTokenValidator,
    IOptions<AuthorizationRequestOptions> requestOptions) : IAuthorizationResponseHandler
{
    public async Task<AuthorizationResult> HandleAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>> parameters,
        CancellationToken cancellationToken = default)
    {
        // Read the parameters. Nothing is verified yet, and a shape no specification defines is refused
        // here rather than resolved - a response carrying both a code and an error, or neither.
        var response = parser.Parse(parameters);
        RefuseMalformed(response);

        // Locate the stored login this response names, WITHOUT spending it yet. This is the first half
        // of the CSRF gate (RFC 6749 section 10.12): a response naming no login of ours is refused
        // before its contents matter. The look-up also yields the issuer this login was started with,
        // which the next check needs. It deliberately does not remove the login, because the checks
        // still to come can fail, and spending a single-use state on a response that then turns out
        // forged would let anyone who knows the (non-secret) state value burn a victim's sign-in.
        var context = await stateConsumer.FindAsync(response.State, cancellationToken);

        // An ID Token that came from the authorization endpoint carries its own issuer, and the response
        // then states its issuer twice. RFC 9207 section 4 makes that a check in its own right - "if a
        // client receives an authorization response that contains multiple issuer identifiers, the client
        // MUST reject the response if these issuer identifiers do not match" - which comparing each one
        // against the expected value separately cannot perform. It also sanctions the parameter's absence
        // in this case, since the ID Token already names the issuer.
        // Validating the token here, before the issuer check, is what makes its claim available. The token
        // is verified against the provider's published keys, so its issuer is an assertion the provider
        // signed rather than a value the response asserted about itself.
        var identityToken = await ValidateIdentityTokenAsync(response, context, cancellationToken);

        // Confirm the response came from the provider this login was started with, and do it BEFORE
        // reading the error code. RFC 9207 section 2.4: "For error responses, clients MUST NOT assume
        // that the error originates from the intended authorization server." An error code logged or
        // shown before this check is an attacker's claim recorded as the provider's.
        await issuerValidator.ValidateAsync(
            new ResponseIssuers
            {
                Expected = context.Issuer,
                Parameter = response.Issuer,
                IdentityTokenClaim = identityToken?.Payload.Issuer,
            },
            cancellationToken);

        // Everything that can still refuse this response runs BEFORE the login is spent. Spending is
        // irreversible, and the state value is not a secret - it travels in the request URL - so a check
        // that rejects after the spend lets anyone who saw that value burn the victim's pending sign-in
        // with a response their own provider would never have sent.
        var result = response.Kind == AuthorizationResponseKind.Error
            ? null
            : new AuthorizationResult(context)
            {
                Code = response.Code,
                IdToken = identityToken,
                AccessToken = response.AccessToken,
                TokenType = response.TokenType,
                ExpiresIn = ParseExpiresIn(response.ExpiresIn),
                Scope = response.Scope,
            };

        // Now the response has earned it. Both a success and a provider error are spent, since neither may
        // be replayed; a login already spent between the look-up and here is a replay and is refused.
        // Removal is atomic, so of two callbacks racing on one state exactly one gets this far.
        // response.State is non-null here - FindAsync would have thrown Missing for a null one.
        await stateConsumer.ConsumeAsync(response.State!, cancellationToken);

        return result ?? throw new AuthorizationResponseException(
            $"The provider '{context.Issuer}' refused the authorization request: {response.Error}.",
            response.Error!,
            response.ErrorDescription);
    }

    /// <summary>
    /// Validates an ID Token the response carried, with the artifacts beside it as its binding inputs.
    /// </summary>
    /// <remarks>
    /// The nonce ties the token to this login, and c_hash/at_hash tie it to whatever came beside it in
    /// the same response. Both neighbours are in hand only here: after a token exchange the code is spent
    /// and there would be nothing left to check c_hash against.
    /// The artifacts are checked against the configured flow first, so a token the client never asked for
    /// is refused rather than validated - validating it would be doing work on behalf of an artifact that
    /// has no business being in the response at all.
    /// </remarks>
    private async Task<JsonWebToken?> ValidateIdentityTokenAsync(
        AuthorizationResponse response,
        AuthorizationContext context,
        CancellationToken cancellationToken)
    {
        if (response.Kind == AuthorizationResponseKind.Error)
            return null;

        RequireArtifactsMatchTheFlow(response, requestOptions.Value.Flow);

        if (response.IdToken is not { } identityToken)
            return null;

        return await identityTokenValidator.ValidateAsync(
            identityToken,
            new IdentityTokenValidationContext
            {
                Nonce = context.Nonce,
                AuthorizationCode = response.Code,
                AccessToken = response.AccessToken,
            },
            cancellationToken);
    }

    /// <summary>
    /// Refuses a response whose artifacts are not the ones the configured flow asks for.
    /// </summary>
    /// <remarks>
    /// Both directions matter, and the surprising one is the extra artifact. A client that asked for a
    /// code and receives a code plus an ID Token has been handed something it never requested, by a party
    /// it has not finished authenticating; accepting the useful parts of such a response is how a client
    /// ends up trusting an artifact no check of its own asked for. Missing artifacts are refused for the
    /// plainer reason that the flow cannot be completed without them.
    /// This is what makes the opt-in real on the receiving side: opting out of a flow means responses for
    /// it are refused, not merely never requested.
    /// </remarks>
    private static void RequireArtifactsMatchTheFlow(AuthorizationResponse response, AuthorizationFlow flow)
    {
        RequireArtifact(response.Code is not null, flow.IncludesAuthorizationCode(), "an authorization code", flow);
        RequireArtifact(response.IdToken is not null, flow.IncludesIdentityToken(), "an ID Token", flow);
        RequireArtifact(response.AccessToken is not null, flow.IncludesAccessToken(), "an access token", flow);
    }

    private static void RequireArtifact(bool present, bool expected, string artifact, AuthorizationFlow flow)
    {
        if (present == expected)
            return;

        var problem = present ? "carries" : "is missing";
        throw new AuthorizationResponseException(
            $"The authorization response {problem} {artifact}, which the '{flow.ToResponseType()}' flow "
            + (present ? "did not ask for." : "requires."));
    }

    /// <summary>
    /// Reads the stated lifetime, or returns null when the provider gave none or gave one that does not
    /// read as a number of seconds.
    /// </summary>
    /// <remarks>
    /// A lifetime that cannot be read is reported as unknown rather than failing the response: RFC 6749
    /// section 4.2.2 makes expires_in RECOMMENDED, not required, so a client that cannot use it is in the
    /// same position as one that was never told.
    /// </remarks>
    private static TimeSpan? ParseExpiresIn(string? expiresIn)
        => long.TryParse(expiresIn, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            ? TimeSpan.FromSeconds(seconds)
            : null;

    /// <summary>
    /// Rejects the two shapes no specification defines, before any state is consumed or trusted.
    /// </summary>
    /// <remarks>
    /// Done ahead of consuming the state so a malformed response cannot burn a legitimate login: a
    /// well-formed response is always exactly one of a code or an error, so anything else is not a
    /// response to spend a stored state on. See <see cref="AuthorizationResponseKind"/> for why the
    /// contradictory case is refused rather than resolved to one reading or the other.
    /// </remarks>
    private static void RefuseMalformed(AuthorizationResponse response)
    {
        switch (response.Kind)
        {
            case AuthorizationResponseKind.Success:
            case AuthorizationResponseKind.Error:
                return;

            case AuthorizationResponseKind.Contradictory:
                throw new AuthorizationResponseException(
                    "The authorization response carries both success parameters and an error, which no "
                    + "specification defines. Reading it as either would act on half of a response the provider "
                    + "did not send.");

            case AuthorizationResponseKind.Unrecognized:
                throw new AuthorizationResponseException(
                    "The request reaching the callback address is not an authorization response: it carries "
                    + "neither a code, a token, nor an error. A token-returning response delivered by "
                    + "fragment looks like this too, since a fragment never reaches the server.");

            default:
                throw new AuthorizationResponseException(
                    $"The authorization response is of an unknown kind '{response.Kind}'.");
        }
    }
}
