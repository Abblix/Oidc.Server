// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Reads the consents the host keeps for an authorization request, in a stage of its own, as the request's
/// <c>prompt=consent</c> leaves them, and answers a request whose consent is still pending.
/// </summary>
/// <param name="consentsProvider">The host's consents.</param>
/// <param name="clock">Stamps the consent page a request is sent to.</param>
internal sealed class UserConsentsReader(IUserConsentsProvider consentsProvider, TimeProvider clock)
{
    /// <summary>
    /// The consents the request proceeds with.
    /// </summary>
    /// <remarks>
    /// Observed and decided here rather than by decorators around the host's provider, so a host replacing its
    /// provider keeps both the stage's span and the prompt.
    /// </remarks>
    public async Task<UserConsents> ReadAsync(ValidAuthorizationRequest request, AuthSession authSession)
    {
        var hostConsents = await StageObservation.RunAsync(
            TelemetryStages.Consent,
            () => consentsProvider.GetUserConsentsAsync(request, authSession),
            StageObservation.NeverRefused);

        return ConsentAskedOf(request, hostConsents);
    }

    /// <summary>
    /// The answer a request gets while consent for some of what it asks is still pending, or null when none is.
    /// </summary>
    public AuthorizationResponse? StillOwed(
        ValidAuthorizationRequest request,
        AuthSession authSession,
        UserConsents userConsents)
    {
        var model = request.Model;

        // If consent for required scopes, resources, or authorization_details is still pending, handle it.
        if (userConsents.Pending is { Scopes.Length: > 0 }
            or { Resources.Length: > 0 }
            or { AuthorizationDetails.Count: > 0 })
        {
            // If user interaction is disallowed but consent is necessary, return an error.
            if (PromptPages.Asks(model, Prompts.None))
            {
                return new AuthorizationError(
                    model,
                    ErrorCodes.ConsentRequired,
                    "The Authorization Server requires End-User consent.",
                    request.ResponseMode,
                    model.RedirectUri);
            }

            // Prompt for consent if necessary permissions are not yet granted.
            // A request asking for consent is stamped, so the consent the host records on that page answers it
            var consentPage = PromptPages.Asks(model, Prompts.Consent)
                ? PromptPages.Stamped(model, Prompts.Consent, clock.GetUtcNow())
                : model;
            return new ConsentRequired(consentPage, authSession, userConsents.Pending);
        }

        return null;
    }

    /// <summary>
    /// The host's consents, or everything the request asks for pending while it asks for consent (OIDC Core section
    /// 3.1.2.1, <c>prompt=consent</c>) and the end user has not given it on this request's consent page, as
    /// <see cref="UserConsents.GivenAt"/> tells.
    /// </summary>
    /// <remarks>
    /// A consent the host records no moment for, as one the server grants on its own, never answers the prompt.
    /// </remarks>
    private static UserConsents ConsentAskedOf(ValidAuthorizationRequest request, UserConsents consents)
    {
        if (!PromptPages.Asks(request.Model, Prompts.Consent) ||
            PromptPages.AnsweredBy(request.Model, Prompts.Consent, consents.GivenAt))
        {
            return consents;
        }

        return new UserConsents
        {
            Pending = new(request.Scope, request.Resources)
            {
                AuthorizationDetails = request.AuthorizationDetails,
            },
        };
    }
}
