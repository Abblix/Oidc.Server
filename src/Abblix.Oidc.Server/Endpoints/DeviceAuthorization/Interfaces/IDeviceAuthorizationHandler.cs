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

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for handling device authorization requests as specified in RFC 8628.
/// </summary>
public interface IDeviceAuthorizationHandler
{
    /// <summary>
    /// Handles a device authorization request, validating and processing it to generate
    /// device_code and user_code for the client.
    /// </summary>
    /// <param name="request">The device authorization request from the client.</param>
    /// <param name="clientRequest">The client authentication information.</param>
    /// <returns>
    /// A task that returns a result containing either a successful device authorization response
    /// with device_code and user_code, or an OIDC error.
    /// </returns>
    Task<Result<DeviceAuthorizationResponse, OidcError>> HandleAsync(
        DeviceAuthorizationRequest request,
        ClientRequest clientRequest);
}
