// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
