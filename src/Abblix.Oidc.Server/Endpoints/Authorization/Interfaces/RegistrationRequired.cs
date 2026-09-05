// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Outcome signalling that the host must surface its account-creation UI: the client requested
/// user registration via <c>prompt=create</c> (Initiating User Registration via OpenID Connect 1.0).
/// Per that specification the registration experience is shown regardless of whether the user
/// currently has an authenticated session.
/// </summary>
public record RegistrationRequired(AuthorizationRequest Model)
    : AuthorizationResponse(Model);
