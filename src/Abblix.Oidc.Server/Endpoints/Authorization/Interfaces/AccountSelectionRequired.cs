// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that more than one active end-user session matches the request and the
/// host UI must let the user pick one before authorization can continue. Maps to OpenID Connect
/// Core 1.0 §3.1.2.6 <c>account_selection_required</c> when <c>prompt=none</c>; otherwise the
/// host renders an account picker over the supplied <see cref="Users"/> set.
/// </summary>
/// <param name="Model">The authorization request that triggered the multi-account branch.</param>
/// <param name="Users">All authenticated sessions that satisfy the request's filters
/// (e.g. <c>max_age</c>, <c>acr_values</c>) and are eligible for selection.</param>
public record AccountSelectionRequired(AuthorizationRequest Model, AuthSession[] Users)
    : AuthorizationResponse(Model);
