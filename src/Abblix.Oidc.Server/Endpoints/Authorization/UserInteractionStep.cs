// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInteraction;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Asks the host whether the end user owes a step of its own before the request is authorized.
/// </summary>
/// <param name="interactionRequirement">The host's steps.</param>
internal sealed class UserInteractionStep(IUserInteractionRequirement interactionRequirement)
{
    /// <summary>
    /// The answer a request gets while the end user of <paramref name="authSession"/> owes a step, or null when they
    /// owe none.
    /// </summary>
    public async Task<AuthorizationResponse?> OwedAsync(ValidAuthorizationRequest request, AuthSession authSession)
    {
        if (!await interactionRequirement.IsRequiredAsync(request, authSession))
            return null;

        var model = request.Model;

        // OpenID Connect Core 1.0, section 3.1.2.6: interaction_required "MAY be returned when the prompt parameter
        // value in the Authentication Request is none, but the Authentication Request cannot be completed without
        // displaying a user interface for End-User interaction"
        if (PromptPages.Asks(model, Prompts.None))
        {
            return new AuthorizationError(
                model,
                ErrorCodes.InteractionRequired,
                "The Authorization Server requires End-User interaction.",
                request.ResponseMode,
                model.RedirectUri);
        }

        return new InteractionRequired(model, authSession);
    }
}
