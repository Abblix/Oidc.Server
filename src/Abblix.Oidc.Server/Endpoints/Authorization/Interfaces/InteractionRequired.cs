// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInteraction;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that the end user is signed in but must complete a step of the host's own, as
/// <see cref="IUserInteractionRequirement"/> answered, before the authorization request is fulfilled. Maps to
/// OpenID Connect Core 1.0 section 3.1.2.6 <c>interaction_required</c> when <c>prompt=none</c>.
/// </summary>
/// <param name="Model">The authorization request that triggered the interaction.</param>
/// <param name="AuthSession">The session selected to answer the request, whose end user completes the step.</param>
public record InteractionRequired(AuthorizationRequest Model, AuthSession AuthSession)
    : AuthorizationResponse(Model);
