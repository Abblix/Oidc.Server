// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting a back-channel authentication response to be sent to a client or external system.
/// </summary>
public interface IBackChannelAuthenticationResponseFormatter
{
    /// <summary>
    /// Formats a back-channel authentication response asynchronously.
    /// </summary>
    /// <param name="request">The back-channel authentication request.</param>
    /// <param name="clientRequest">The client request containing authentication details
    /// (needed to determine the correct <c>WWW-Authenticate</c> scheme per RFC 6749 Section 5.2).</param>
    /// <param name="response">The back-channel authentication response result to be formatted.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    Task<ActionResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest,
        Result<BackChannelAuthenticationSuccess, OidcError> response);
}
