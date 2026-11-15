// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Formats an authorization response into a <typeparamref name="TResult"/> - delivering it to the client's redirect URI via
/// query, fragment or form_post, redirecting to an interaction page, or surfacing a no-redirect error.
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IAuthorizationResponseFormatter<TResult> where TResult : class
{
    /// <summary>Formats the authorization endpoint result.</summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The encoded authorization response from the core handler.</param>
    /// <returns>A <typeparamref name="TResult"/> delivering the response.</returns>
    Task<TResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response);
}
