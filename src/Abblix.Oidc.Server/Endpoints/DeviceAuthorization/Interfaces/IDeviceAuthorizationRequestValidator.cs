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
/// Defines the contract for validating device authorization requests.
/// </summary>
public interface IDeviceAuthorizationRequestValidator
{
    /// <summary>
    /// Validates a device authorization request, verifying client credentials and request parameters.
    /// </summary>
    /// <param name="request">The device authorization request to validate.</param>
    /// <param name="clientRequest">The client authentication information.</param>
    /// <returns>
    /// A task that returns a result containing either a valid device authorization request
    /// with resolved client information, or an OIDC error.
    /// </returns>
    Task<Result<ValidDeviceAuthorizationRequest, OidcError>> ValidateAsync(
        DeviceAuthorizationRequest request,
        ClientRequest clientRequest);
}
