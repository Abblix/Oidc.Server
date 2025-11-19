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
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements storage for device authorization requests as defined in RFC 8628.
/// Stores requests by device_code (for client polling) with a secondary index by user_code (for user verification).
/// </summary>
/// <param name="storage">The storage system used for persisting device authorization requests.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
/// <param name="options">Configuration options containing device authorization settings.</param>
public class DeviceAuthorizationStorage(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options) : IDeviceAuthorizationStorage
{
    /// <inheritdoc />
    public async Task StoreAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn)
    {
        var storageOptions = new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn };

        // Store the request by device code (primary key for client polling)
        await storage.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            request,
            storageOptions);

        // Store a mapping from user code to device code (for user verification lookup)
        await storage.SetAsync(
            keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode),
            deviceCode,
            storageOptions);
    }

    /// <inheritdoc />
    public Task<DeviceAuthorizationRequest?> TryGetByDeviceCodeAsync(string deviceCode)
        => storage.GetAsync<DeviceAuthorizationRequest>(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            removeOnRetrieval: false);

    /// <inheritdoc />
    public async Task<(string DeviceCode, DeviceAuthorizationRequest Request)?> TryGetByUserCodeAsync(string userCode)
    {
        var deviceCode = await storage.GetAsync<string>(
            keyFactory.DeviceAuthorizationUserCodeKey(userCode),
            removeOnRetrieval: false);

        if (deviceCode == null)
            return null;

        var request = await TryGetByDeviceCodeAsync(deviceCode);
        if (request == null)
            return null;

        return (deviceCode, request);
    }

    /// <inheritdoc />
    public Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request)
    {
        var deviceAuthOptions = options.Value.DeviceAuthorization.NotNull(nameof(OidcOptions.DeviceAuthorization));
        return storage.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            request,
            new StorageOptions { AbsoluteExpirationRelativeToNow = deviceAuthOptions.CodeLifetime });
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string deviceCode)
    {
        var request = await TryGetByDeviceCodeAsync(deviceCode);
        if (request != null)
        {
            await storage.RemoveAsync(keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode));
        }

        await storage.RemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
    }
}
