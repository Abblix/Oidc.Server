// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>
/// Formats a check-session response (the session-management iframe document) into an <see cref="IResult"/>.
/// </summary>
public interface ICheckSessionResponseFormatter
{
    /// <summary>
    /// Formats the check-session response.
    /// </summary>
    /// <param name="response">The check-session response carrying the HTML template.</param>
    /// <returns>An <see cref="IResult"/> that writes the iframe document with a per-request CSP nonce.</returns>
    Task<IResult> FormatResponseAsync(CheckSessionResponse response);
}
