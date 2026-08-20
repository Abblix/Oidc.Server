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
/// Defines the contract for processing validated device authorization requests.
/// </summary>
public interface IDeviceAuthorizationRequestProcessor
{
    /// <summary>
    /// Processes a validated device authorization request, generating device_code and user_code,
    /// and storing the request for later verification.
    /// </summary>
    /// <param name="request">The validated device authorization request.</param>
    /// <returns>
    /// A task that returns a result containing either a successful device authorization response
    /// or an OIDC error.
    /// </returns>
    Task<Result<DeviceAuthorizationResponse, OidcError>> ProcessAsync(ValidDeviceAuthorizationRequest request);
}
