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
/// Outcome signalling that the host must surface its login UI: either no eligible session
/// exists, or the client requested forced reauthentication via <c>prompt=login</c> /
/// <c>max_age</c>. Maps to OpenID Connect Core 1.0 section 3.1.2.6 <c>login_required</c>
/// when <c>prompt=none</c>.
/// </summary>
public record LoginRequired(AuthorizationRequest Model)
    : AuthorizationResponse(Model);
