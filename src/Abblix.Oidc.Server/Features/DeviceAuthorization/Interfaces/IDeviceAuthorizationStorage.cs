// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Updates an existing device authorization request in storage, refreshing its cache entry with the
    /// caller-supplied remaining lifetime.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <param name="request">The updated device authorization request.</param>
    /// <param name="expiresIn">The remaining lifetime to apply as the cache TTL. The caller derives it from
    /// the request's fixed expiry (RFC 8628 §3.2) so that repeated polling cannot extend the code.</param>
    /// <returns>A task that completes when the request is updated.</returns>
    Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn);

    /// <summary>
    /// Removes a device authorization request from storage using its device code.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A task that completes when the request is removed from storage.</returns>
    Task RemoveAsync(string deviceCode);

    /// <summary>
    /// Atomically attempts to remove a device authorization request by its device code.
    /// This operation is thread-safe and returns whether the removal was successful.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <param name="userCode">The user code for cleaning up the secondary index mapping.</param>
    /// <returns>
    /// A task that returns true when this caller removed the request AND still held its own claim
    /// afterwards. False otherwise, which is wider than "somebody else got it": it also covers the
    /// request not being there and a claim that expired while a store call was in flight - the second
    /// on one caller with nobody to lose to, and its outcome is the request gone with nobody able to be
    /// told they took it. An operator told a second request was the cause goes looking for a second node,
    /// and that case is exactly the one which never produces one. A failure of the second store call,
    /// which removes the user-code index, raises rather than answering: the device code is already
    /// consumed and the caller is handed the exception.
    /// </returns>
    Task<bool> TryRemoveAsync(string deviceCode, string userCode);
}
