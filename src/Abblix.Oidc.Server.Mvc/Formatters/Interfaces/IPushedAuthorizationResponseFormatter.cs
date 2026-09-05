// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines the interface for formatting responses to pushed authorization requests.
/// </summary>
public interface IPushedAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats the response to a pushed authorization request.
    /// </summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The response from processing the authorization request,
    /// which could be a successful pushed authorization response or an error.</param>
    /// <returns>A task that resolves to an action result suitable for returning from an MVC action,
    /// representing the formatted response.</returns>
    Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        Endpoints.Authorization.Interfaces.AuthorizationResponse response);
}
