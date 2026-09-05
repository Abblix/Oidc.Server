// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that an end-user is signed in but additional UI interaction (a step-up,
/// missing claim, MFA challenge or similar) must complete before the authorization request
/// can be fulfilled. Maps to OpenID Connect Core 1.0 §3.1.2.6
/// <c>interaction_required</c> when <c>prompt=none</c>.
/// </summary>
/// <param name="Model">The authorization request that triggered the interaction.</param>
/// <param name="User">The current user, exposed so the host UI can address the prompt to them.</param>
public record InteractionRequired(AuthorizationRequest Model, ClaimsPrincipal User)
    : AuthorizationResponse(Model);
