// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that the user is authenticated but has not yet granted every scope or
/// resource the client is asking for, so the host must show its consent UI for the deltas in
/// <see cref="RequiredUserConsents"/>. Maps to OpenID Connect Core 1.0 section 3.1.2.6
/// <c>consent_required</c> when <c>prompt=none</c>.
/// </summary>
/// <param name="Model">The authorization request that produced the pending-consent state.</param>
/// <param name="AuthSession">The user's current authenticated session.</param>
/// <param name="RequiredUserConsents">The scopes and resources that are still missing
/// approval; everything not listed here is already granted.</param>
public record ConsentRequired(AuthorizationRequest Model, AuthSession AuthSession, ConsentDefinition RequiredUserConsents)
    : AuthorizationResponse(Model);
