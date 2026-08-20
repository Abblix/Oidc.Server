// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Represents an authorized grant result for a refresh token request.
/// Contains the authenticated session, authorization context, and the associated refresh token.
/// </summary>
/// <param name="AuthSession">The authenticated user session, which includes information about the user's
/// authentication state.</param>
/// <param name="Context">The authorization context containing details about the current authorization process,
/// such as requested scopes and client information.</param>
/// <param name="RefreshToken">The refresh token associated with the authorized grant,
/// used to obtain new access tokens without requiring further user interaction.</param>
public record RefreshTokenAuthorizedGrant(
    AuthSession AuthSession,
    AuthorizationContext Context,
    JsonWebToken RefreshToken)
    : AuthorizedGrant(AuthSession, Context);
