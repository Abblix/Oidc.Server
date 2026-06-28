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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Microsoft.AspNetCore.Http;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats an authorization response into an <see cref="IResult"/> — delivering it to the client's redirect URI via
/// query, fragment or form_post, redirecting to an interaction page, or surfacing a no-redirect error.
/// </summary>
public interface IAuthorizationResultFormatter
{
    /// <summary>Formats the authorization endpoint result.</summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The encoded authorization response from the core handler.</param>
    /// <returns>An <see cref="IResult"/> delivering the response.</returns>
    Task<IResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response);
}
