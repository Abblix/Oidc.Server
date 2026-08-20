// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting a response to a low-level object with the content of an OpenID Provider (OP) check-session frame.
/// </summary>
public interface ICheckSessionResponseFormatter
{
    /// <summary>
    /// Formats a response asynchronously to a low-level object with the content of an OpenID Provider (OP) check-session frame.
    /// </summary>
    /// <param name="response">The check-session response to be formatted.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    Task<ActionResult> FormatResponseAsync(CheckSessionResponse response);
}
