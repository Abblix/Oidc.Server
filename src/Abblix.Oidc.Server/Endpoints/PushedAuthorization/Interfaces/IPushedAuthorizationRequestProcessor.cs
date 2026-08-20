// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Processes valid pushed authorization requests, generating a response that includes
/// the request's URI and its expiration.
/// </summary>
public interface IPushedAuthorizationRequestProcessor
{
    /// <summary>
    /// Asynchronously processes a valid authorization request and generates a response.
    /// </summary>
    /// <param name="request">The valid authorization request to process.</param>
    /// <returns>A task that resolves to an authorization response, including the
    /// request URI and expiration time.</returns>
    Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request);
}
