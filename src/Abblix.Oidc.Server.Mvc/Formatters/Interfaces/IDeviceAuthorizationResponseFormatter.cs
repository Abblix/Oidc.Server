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
/// Defines the contract for formatting device authorization responses.
/// </summary>
public interface IDeviceAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats a device authorization response into an HTTP response.
    /// </summary>
    /// <param name="request">The original device authorization request.</param>
    /// <param name="response">The device authorization response to format.</param>
    /// <returns>A task that returns the formatted response as an ActionResult.</returns>
    Task<ActionResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<DeviceAuthorizationResponse, OidcError> response);
}
