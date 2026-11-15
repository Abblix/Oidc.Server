// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using DeviceAuthorizationRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;
using DeviceAuthorizationResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Formats the result of a device authorization request (RFC 8628) into a <typeparamref name="TResult"/> (the device-code
/// response on success or the OAuth error otherwise).
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IDeviceAuthorizationResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the device authorization endpoint result.
    /// </summary>
    /// <param name="request">The core device authorization request being answered.</param>
    /// <param name="response">The success-or-error result produced by the device authorization handler.</param>
    /// <returns>A <typeparamref name="TResult"/> carrying the device-code response or the formatted error.</returns>
    Task<TResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<DeviceAuthorizationResponse, OidcError> response);
}
