// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting a response when reading client information as a low-level response object to return it to the client.
/// </summary>
public interface IReadClientResponseFormatter
{
    /// <summary>
    /// Formats a response asynchronously when reading client information as a low-level response object to return it to the client.
    /// </summary>
    /// <param name="request">The client information request.</param>
    /// <param name="response">The response containing client information to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(ClientRequest request, Result<ReadClientSuccessfulResponse, OidcError> response);
}
