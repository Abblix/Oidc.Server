// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Formats a check-session response (the session-management iframe document) into a <typeparamref name="TResult"/>.
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface ICheckSessionResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the check-session response.
    /// </summary>
    /// <param name="response">The check-session response carrying the HTML template.</param>
    /// <returns>A <typeparamref name="TResult"/> that writes the iframe document with a per-request CSP nonce.</returns>
    Task<TResult> FormatResponseAsync(CheckSessionResponse response);
}
