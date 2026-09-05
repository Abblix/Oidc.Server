// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Microsoft.AspNetCore.Http;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>
/// Formats an authorization response into an <see cref="IResult"/> - delivering it to the client's redirect URI via
/// query, fragment or form_post, redirecting to an interaction page, or surfacing a no-redirect error.
/// </summary>
public interface IAuthorizationResponseFormatter
{
    /// <summary>Formats the authorization endpoint result.</summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The encoded authorization response from the core handler.</param>
    /// <returns>An <see cref="IResult"/> delivering the response.</returns>
    Task<IResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response);
}
