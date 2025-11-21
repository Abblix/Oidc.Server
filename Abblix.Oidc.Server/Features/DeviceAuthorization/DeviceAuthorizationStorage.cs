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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements storage for device authorization requests as defined in RFC 8628.
/// Stores requests by device_code (for client polling) with a secondary index by user_code (for user verification).
/// Uses atomic distributed cache operations to prevent race conditions in token issuance.
/// </summary>
/// <param name="cache">The distributed cache backend used for atomic operations.</param>
/// <param name="serializer">The serializer for converting objects to/from binary format.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
/// <param name="options">Configuration options containing device authorization settings.</param>
public class DeviceAuthorizationStorage(
    IDistributedCache cache,
    IBinarySerializer serializer,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options) : IDeviceAuthorizationStorage
{
    /// <inheritdoc />
    public async Task StoreAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn)
    {
        var cacheOptions = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = expiresIn };

        // Store the request by device code (primary key for client polling)
        await cache.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            serializer.Serialize(request),
            cacheOptions);

        // Store a mapping from user code to device code (for user verification lookup)
        await cache.SetAsync(
            keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode),
            serializer.Serialize(deviceCode),
            cacheOptions);
    }

    /// <inheritdoc />
    public async Task<DeviceAuthorizationRequest?> TryGetByDeviceCodeAsync(string deviceCode)
    {
        var data = await cache.GetAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
        return data != null ? serializer.Deserialize<DeviceAuthorizationRequest>(data) : null;
    }

    /// <inheritdoc />
    public async Task<(string DeviceCode, DeviceAuthorizationRequest Request)?> TryGetByUserCodeAsync(string userCode)
    {
        var deviceCodeData = await cache.GetAsync(keyFactory.DeviceAuthorizationUserCodeKey(userCode));
        if (deviceCodeData == null)
            return null;

        var deviceCode = serializer.Deserialize<string>(deviceCodeData);
        var request = await TryGetByDeviceCodeAsync(deviceCode!);
        if (request == null)
            return null;

        return (deviceCode!, request);
    }

    /// <inheritdoc />
    public Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request)
    {
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));
        return cache.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            serializer.Serialize(request),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.CodeLifetime });
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string deviceCode)
    {
        var request = await TryGetByDeviceCodeAsync(deviceCode);
        if (request != null)
        {
            await cache.RemoveAsync(keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode));
        }

        await cache.RemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
    }

    /// <summary>
    /// Atomically attempts to remove a device authorization request by device code.
    /// Uses lock-based atomic removal protocol to prevent race conditions where multiple threads
    /// attempt to remove the same device code concurrently.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method performs atomic removal of both the device code entry and its associated user code
    /// mapping. By accepting the userCode as a parameter, it avoids an additional cache read operation,
    /// since the caller already has this information from a previous fetch.
    /// </para>
    /// <para>
    /// <strong>Use Case:</strong> This method is used in the Device Authorization Grant flow (RFC 8628)
    /// when exchanging an authorized device code for tokens. The atomic removal ensures that concurrent
    /// token requests cannot both claim the same device code.
    /// </para>
    /// <para>
    /// <strong>Atomicity:</strong> Uses <see cref="DistributedCacheExtensions.TryRemoveAsync"/>
    /// which implements a lock-based protocol ensuring exactly one thread successfully removes the value
    /// even in concurrent scenarios. After successful removal, cleans up the user code mapping.
    /// </para>
    /// </remarks>
    /// <param name="deviceCode">The device code identifying the authorization request to remove.</param>
    /// <param name="userCode">The user code for cleaning up the secondary index mapping.</param>
    /// <returns>
    /// A task that completes when the operation finishes, containing true if the request was successfully
    /// removed by this thread; false if another thread won the race or the device code didn't exist.
    /// </returns>
    public async Task<bool> TryRemoveAsync(string deviceCode, string userCode)
    {
        var removed = await cache.TryRemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
        if (!removed)
            return false;

        await cache.RemoveAsync(keyFactory.DeviceAuthorizationUserCodeKey(userCode));
        return true;
    }
}
