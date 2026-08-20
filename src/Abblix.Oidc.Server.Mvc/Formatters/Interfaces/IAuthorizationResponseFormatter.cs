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
/// Defines an interface for formatting an authorization response from a strong-typed model
/// to a framework-specific response.
/// </summary>
public interface IAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats an authorization response asynchronously, converting it from a strong-typed model to a framework-specific response.
    /// </summary>
    /// <param name="request">The authorization request.</param>
    /// <param name="response">The authorization response to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, with the formatted response.</returns>
    Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        Endpoints.Authorization.Interfaces.AuthorizationResponse response);
}