// Abblix OIDC Client Library
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

using System.Security.Claims;
using Abblix.Jwt;

namespace Abblix.Oidc.Client.Features.Principal;

/// <summary>
/// Turns a validated ID Token into the principal the host will treat as the signed-in user.
/// </summary>
/// <remarks>
/// A seam rather than a private step, because what a host wants in its principal is its own: which claim is
/// the display name, where roles come from, whether UserInfo claims are folded in. The default answers the
/// protocol's question only - the token's claims, unchanged - and a host that needs more replaces it.
/// </remarks>
public interface IClaimsPrincipalFactory
{
    /// <summary>
    /// Builds the principal for the user the given ID Token describes.
    /// </summary>
    /// <param name="identityToken">
    /// The ID Token, already validated. Building a principal from an unvalidated one would hand the host a
    /// signed-in user on the strength of a string somebody sent.
    /// </param>
    /// <returns>The principal representing the signed-in user.</returns>
    ClaimsPrincipal Create(JsonWebToken identityToken);
}
