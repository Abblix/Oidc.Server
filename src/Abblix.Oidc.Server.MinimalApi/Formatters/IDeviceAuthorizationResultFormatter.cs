// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using DeviceAuthorizationRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;
using DeviceAuthorizationResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats the result of a device authorization request (RFC 8628) into an <see cref="IResult"/> (the device-code
/// response on success or the OAuth error otherwise).
/// </summary>
public interface IDeviceAuthorizationResultFormatter
{
    /// <summary>
    /// Formats the device authorization endpoint result.
    /// </summary>
    /// <param name="request">The core device authorization request being answered.</param>
    /// <param name="response">The success-or-error result produced by the device authorization handler.</param>
    /// <returns>An <see cref="IResult"/> carrying the device-code response or the formatted error.</returns>
    Task<IResult> FormatResponseAsync(
        DeviceAuthorizationRequest request,
        Result<DeviceAuthorizationResponse, OidcError> response);
}
