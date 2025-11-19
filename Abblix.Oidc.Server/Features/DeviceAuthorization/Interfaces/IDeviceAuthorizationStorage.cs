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

namespace Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;

/// <summary>
/// Defines the contract for a storage system responsible for persisting and retrieving
/// device authorization requests as defined in RFC 8628.
/// </summary>
public interface IDeviceAuthorizationStorage
{
    /// <summary>
    /// Stores a device authorization request with the specified device code.
    /// </summary>
    /// <param name="deviceCode">The unique device code identifier.</param>
    /// <param name="request">The device authorization request to store.</param>
    /// <param name="expiresIn">The duration after which the stored request will expire.</param>
    /// <returns>A task that completes when the request is stored.</returns>
    Task StoreAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn);

    /// <summary>
    /// Tries to retrieve a device authorization request by its device code.
    /// This is used by the client when polling the token endpoint.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>
    /// A task that returns the device authorization request if found; otherwise, null.
    /// </returns>
    Task<DeviceAuthorizationRequest?> TryGetByDeviceCodeAsync(string deviceCode);

    /// <summary>
    /// Tries to retrieve a device authorization request by its user code.
    /// This is used during user verification to look up the pending request.
    /// </summary>
    /// <param name="userCode">The user-friendly verification code.</param>
    /// <returns>
    /// A task that returns the device code and request if found; otherwise, null.
    /// </returns>
    Task<(string DeviceCode, DeviceAuthorizationRequest Request)?> TryGetByUserCodeAsync(string userCode);

    /// <summary>
    /// Updates an existing device authorization request in storage.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <param name="request">The updated device authorization request.</param>
    /// <returns>A task that completes when the request is updated.</returns>
    Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request);

    /// <summary>
    /// Removes a device authorization request from storage using its device code.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A task that completes when the request is removed from storage.</returns>
    Task RemoveAsync(string deviceCode);
}
