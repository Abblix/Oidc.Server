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
/// <c>prompt=consent</c> leaves them.
/// </summary>
/// <param name="consentsProvider">The host's consents.</param>
internal sealed class UserConsentsReader(IUserConsentsProvider consentsProvider)
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
