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

using Abblix.Oidc.Client.Features.AuthorizationState;

namespace Abblix.Oidc.Client.Features.AuthorizationResponses;

/// <summary>
/// Runs an authorization response through parsing, issuer verification and state consumption, in the
/// one order that makes each step safe.
/// </summary>
/// <param name="parser">Takes the response apart without judging it.</param>
/// <param name="stateConsumer">Matches the response to a held login and consumes it, once.</param>
/// <param name="issuerValidator">Confirms the response came from the provider the login was started with.</param>
internal sealed class AuthorizationResponseHandler(
    IAuthorizationResponseParser parser,
    IAuthorizationStateConsumer stateConsumer,
    IResponseIssuerValidator issuerValidator) : IAuthorizationResponseHandler
{
    public async Task<AuthorizationCodeResult> HandleAsync(
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
        var state = await stateConsumer.FindAsync(response.State, cancellationToken);

        // Confirm the response came from the provider this login was started with, and do it BEFORE
        // reading the error code. RFC 9207 section 2.4: "For error responses, clients MUST NOT assume
        // that the error originates from the intended authorization server." An error code logged or
        // shown before this check is an attacker's claim recorded as the provider's.
        // No id_token arrives at the authorization endpoint in the code flow, so the only issuer the
        // response offers is the iss parameter; the ID Token claim is left null.
        await issuerValidator.ValidateAsync(
            new ResponseIssuers { Expected = state.Issuer, Parameter = response.Issuer },
            cancellationToken);

        // Now the response has earned it: spend the single-use state. Both a success and a provider
        // error are spent, since neither may be replayed; a login already spent between the look-up and
        // here is a replay and is refused. response.State is non-null here - FindAsync would have thrown
        // Missing for a null one.
        await stateConsumer.ConsumeAsync(response.State!, cancellationToken);

        // Only now, with the response known to come from the right provider and its login spent, is its
        // outcome acted on.
        return response.Kind switch
        {
            AuthorizationResponseKind.AuthorizationCode => new AuthorizationCodeResult(response.Code!, state),

            AuthorizationResponseKind.Error => throw new AuthorizationResponseException(
                $"The provider '{state.Issuer}' refused the authorization request: {response.Error}.",
                response.Error!,
                response.ErrorDescription),

            // RefuseMalformed already rejected the other two kinds, so reaching them here would mean the
            // response changed underfoot. Fail loudly rather than pick a branch by accident.
            _ => throw new AuthorizationResponseException(
                $"The authorization response is of an unexpected kind '{response.Kind}' after validation."),
        };
    }

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
            case AuthorizationResponseKind.AuthorizationCode:
            case AuthorizationResponseKind.Error:
                return;

            case AuthorizationResponseKind.Contradictory:
                throw new AuthorizationResponseException(
                    "The authorization response carries both a code and an error, which no specification "
                    + "defines. Reading it as either would act on half of a response the provider did not send.");

            case AuthorizationResponseKind.Unrecognized:
                throw new AuthorizationResponseException(
                    "The request reaching the callback address is not an authorization response: it carries "
                    + "neither a code nor an error.");

            default:
                throw new AuthorizationResponseException(
                    $"The authorization response is of an unknown kind '{response.Kind}'.");
        }
    }
}
