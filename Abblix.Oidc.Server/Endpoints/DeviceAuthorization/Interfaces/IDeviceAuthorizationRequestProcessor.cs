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
