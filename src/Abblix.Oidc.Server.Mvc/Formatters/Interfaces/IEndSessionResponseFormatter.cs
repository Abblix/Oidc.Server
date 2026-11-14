// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting a response to an end-session request and response.
/// </summary>
public interface IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats a response asynchronously for an end-session request and response.
    /// </summary>
    /// <param name="request">The end-session request as it arrived, its <c>post_logout_redirect_uri</c> unchecked:
    /// the address a successful logout may send the end user to is the one the response carries, and an address the
    /// request names but no client confirms is dropped there.</param>
    /// <param name="response">The end-session response to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<IEndSessionResponse, OidcError> response);
}
