// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements storage for device authorization requests as defined in RFC 8628.
/// Stores requests by device_code (for client polling) with a secondary index by user_code (for user verification).
/// Redemption of a device code goes through the cache's claim protocol, which narrows the window in which
/// two token requests both claim one code rather than closing it.
/// </summary>
/// <param name="logger">Records a secondary-index entry left behind, which nothing else reports.</param>
/// <param name="cache">The distributed cache backend used for atomic operations.</param>
/// <param name="serializer">The serializer for converting objects to/from binary format.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
/// <param name="timeProvider">Provides the current time for seeding the request's absolute expiry.</param>
public partial class DeviceAuthorizationStorage(
    ILogger<DeviceAuthorizationStorage> logger,
    IDistributedCache cache,
    IBinarySerializer serializer,
    IEntityStorageKeyFactory keyFactory,
    TimeProvider timeProvider) : IDeviceAuthorizationStorage
{
    /// <inheritdoc />
    public async Task StoreAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn)
    {
        // Persist the absolute expiry so a regularly-polling client cannot extend the code: the token
        // endpoint derives the remaining cache TTL from this fixed instant instead of resetting the full
        // lifetime on every poll (RFC 8628 section 3.2)
        request.ExpiresAt = timeProvider.GetUtcNow() + expiresIn;

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
    public Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn)
    {
        // Apply the caller-computed remaining lifetime as the cache TTL. The caller derives it once from the
        // record's fixed ExpiresAt (RFC 8628 section 3.2) and gates on expiry first, so polling cannot extend the
        // code and the TTL here is always positive - no second clock read that could race the expiry boundary
        return cache.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            serializer.Serialize(request),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = expiresIn });
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string deviceCode)
    {
        // The secondary index is best-effort here for the same reason it is in TryRemoveAsync: it is not
        // what the caller asked for. The token endpoint calls this from its expired and denied arms and
        // then returns a grant error, so a store that refuses this write would turn that error into a
        // server fault - the client gets a 500 where it should be told the code expired.
        //
        // Less costly than the same failure in TryRemoveAsync, and worth saying so: nothing has been
        // consumed here, so the request is still live and the client's next poll gets the same answer.
        // The shape is identical though, and leaving one arm best-effort and the other not is how a
        // class comes back.
        var request = await TryGetByDeviceCodeAsync(deviceCode);
        if (request != null)
        {
            var userCodeKey = keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode);
            try
            {
                await cache.RemoveAsync(userCodeKey);
            }
            catch (Exception exception)
            {
                LogUserCodeIndexNotRemoved(exception, userCodeKey);
            }
        }

        // Not guarded. This one IS what the caller asked for, and a failure means the request is still
        // there - swallowing it would report a removal that did not happen.
        await cache.RemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
    }

    /// <summary>
    /// Claims a device authorization request by device code, deciding presence and removing it in one
    /// protocol, so that a caller told it removed the request is the only caller that can be told so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method performs atomic removal of both the device code entry and its associated user code
    /// mapping. By accepting the userCode as a parameter, it avoids an additional cache read operation,
    /// since the caller already has this information from a previous fetch.
    /// </para>
    /// <para>
    /// <strong>Use Case:</strong> This method is used in the Device Authorization Grant flow (RFC 8628)
    /// when exchanging an authorized device code for tokens. The claim keeps two token requests from both
    /// being told they took one device code, however many processes are polling; what it does not stop is
    /// a record RESTORED after the claim by an ungated write, which the next poll then claims in its turn.
    /// That needs no second process and is issue 459. The Atomicity note below says what the claim reaches.
    /// </para>
    /// <para>
    /// <strong>Atomicity:</strong> Uses <see cref="Abblix.Utils.DistributedCacheExtensions.TryRemoveAsync"/>
    /// which admits at most one caller through its lock-token protocol, and serializes redemptions of one
    /// device code in-process, which closes the one way a removal loses its winner to a competitor.
    /// What that does NOT give is a winner for every removal - the code can be consumed with nobody told
    /// they took it, and that needs neither a second caller nor a second node. The extension's own remarks
    /// carry the condition and name the store primitive that closes it. After a successful removal, cleans
    /// up the user code mapping.
    /// </para>
    /// </remarks>
    /// <param name="deviceCode">The device code identifying the authorization request to remove.</param>
    /// <param name="userCode">The user code for cleaning up the secondary index mapping.</param>
    /// <returns>
    /// A task that completes when the operation finishes, containing true when this caller removed the
    /// request AND still held the claim afterwards. False otherwise, which is wider than "another caller
    /// won or it was never there": the code can be consumed and the caller still told false, when the lock
    /// guarding the removal expires mid-protocol. The extension's remarks carry that condition.
    /// <para>
    /// The cleanup below them cannot change that answer either way. Removing the user-code index is a
    /// different question from whether this caller took the code, so a store that refuses it is logged
    /// and the true stands: the entry left behind points at a request that no longer exists and carries
    /// its own expiry.
    /// </para>
    /// </returns>
    public async Task<bool> TryRemoveAsync(string deviceCode, string userCode)
    {
        var removed = await cache.TryRemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
        if (!removed)
            return false;

        // The device code is consumed at this point, and that is the fact the caller asked about. Tidying
        // the secondary index is a different question, so a store that refuses it does not get to take the
        // answer away: the token endpoint calls this inside a `when` clause, where an exception becomes a
        // server fault rather than a grant error - no tokens for a code that can never be presented again,
        // and the end user's approval lost with it.
        //
        // The entry left behind is harmless on its own: it points at a request key that no longer exists,
        // and it carries its own expiry. Removing it FIRST instead would make the fault retryable, at the
        // cost of a window in which the user code resolves to nothing while the device code is still live
        // - a worse trade, because that window is on the path that succeeds.
        //
        // Swallowed, not hidden. Nothing else in the system reports a dangling index, so without this line
        // an operator has no way to learn the store refused a write at all.
        var userCodeKey = keyFactory.DeviceAuthorizationUserCodeKey(userCode);
        try
        {
            await cache.RemoveAsync(userCodeKey);
        }
        catch (Exception exception)
        {
            LogUserCodeIndexNotRemoved(exception, userCodeKey);
        }

        return true;
    }
}
