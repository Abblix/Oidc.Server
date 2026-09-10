// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Implements storage for device authorization requests as defined in RFC 8628.
/// Stores requests by device_code (for client polling) with a secondary index by user_code (for user verification).
/// Redemption of a device code is a removing read, which the storage is required to perform
/// indivisibly - so how far one winner is guaranteed is that storage's answer rather than this
/// class's.
/// </summary>
/// <param name="logger">Records a secondary-index entry left behind, which nothing else reports.</param>
/// <param name="storage">Holds the request and its user-code index, and decides who redeems.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
/// <param name="timeProvider">Provides the current time for seeding the request's absolute expiry.</param>
public partial class DeviceAuthorizationStorage(
    ILogger<DeviceAuthorizationStorage> logger,
    IEntityStorage storage,
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

        var options = new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn };

        // Store the request by device code (primary key for client polling)
        await storage.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            request,
            options);

        // Store a mapping from user code to device code (for user verification lookup)
        await storage.SetAsync(
            keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode),
            deviceCode,
            options);
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
    public Task UpdateAsync(string deviceCode, DeviceAuthorizationRequest request, TimeSpan expiresIn)
    {
        // Apply the caller-computed remaining lifetime as the cache TTL. The caller derives it once from the
        // record's fixed ExpiresAt (RFC 8628 section 3.2) and gates on expiry first, so polling cannot extend the
        // code and the TTL here is always positive - no second clock read that could race the expiry boundary
        return storage.SetAsync(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            request,
            new StorageOptions { AbsoluteExpirationRelativeToNow = expiresIn });
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string deviceCode)
    {
        // The secondary index is best-effort here for the same reason it is in TryRemoveAsync: it is not
        // what the caller asked for. The token endpoint calls this from its expired and denied arms and
        // then returns a grant error, so a store that refuses this write would turn that error into a
        // server fault - the client gets a 500 where it should be told the code expired or was denied.
        //
        // The two arms are NOT the same shape, and the difference is the order. There the claim has
        // already removed the request, so the index is all that is left; here the request is removed
        // AFTER this, so a refusal at this line leaves both keys in place and the removal still runs.
        // What they share is the reason for guarding: the index is never the caller's question, and its
        // store deciding otherwise must not become the caller's answer.
        var request = await TryGetByDeviceCodeAsync(deviceCode);
        if (request != null)
        {
            var userCodeKey = keyFactory.DeviceAuthorizationUserCodeKey(request.UserCode);
            try
            {
                await storage.RemoveAsync(userCodeKey);
            }
            catch (Exception exception)
            {
                LogUserCodeIndexNotRemovedBeforeDiscard(exception, userCodeKey);
            }
        }

        // Not guarded, and the reason is not symmetry with the arm above. Removing the request is the
        // whole of what this method is for, so a store that refuses it has not done the thing asked;
        // reporting otherwise would leave a live record behind a call that looked like it worked. The
        // caller does see a fault where it expected a grant error, which is the cost, and it is a cost
        // over a record that is expired or denied rather than one carrying an approval.
        await storage.RemoveAsync(keyFactory.DeviceAuthorizationRequestKey(deviceCode));
    }

    /// <summary>
    /// Claims a device authorization request by device code, deciding presence and removing it in one
    /// protocol, so that a caller told it removed the request is the only caller that can be told so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method claims the device code and then tidies its user-code index entry. Only the claim is
    /// indivisible; the tidying is a separate call whose failure is logged and swallowed, because
    /// whether the index went is a different question from whether this caller took the code. The user
    /// code is a parameter so that finding the entry costs no extra read, the caller having it already.
    /// </para>
    /// <para>
    /// <strong>Use Case:</strong> This method is used in the Device Authorization Grant flow (RFC 8628)
    /// when exchanging an authorized device code for tokens. The claim keeps two token requests from both
    /// being told they took one device code, however many processes are polling. What it does not reach
    /// is a decision landing after the claim: that path re-reads the record and refuses, which leaves a
    /// window one store round trip wide rather than none. The Atomicity note below says what the claim
    /// itself reaches.
    /// </para>
    /// <para>
    /// <strong>Atomicity:</strong> The claim is a removing read, which <see cref="IEntityStorage"/> requires
    /// to be indivisible, so no competitor can take the code between the read and the removal. How far that
    /// reaches beyond one process is the registered storage's answer: the one built over a distributed cache
    /// serializes redemptions within a process and no further. It covers the claim and nothing after it -
    /// the user-code index is tidied by a later call, and best-effort.
    /// </para>
    /// <para>
    /// One way the code is still consumed with nobody told they took it survives, and it is not a race: the
    /// storage turns the removed bytes back into a record AFTER deleting them, so a record it cannot read -
    /// a shape changed under a rolling deploy, a serializer that dispatches differently between versions -
    /// is gone and the caller gets the failure rather than the code. Nothing here can put it back, because
    /// the delete has already happened at the server.
    /// </para>
    /// </remarks>
    /// <param name="deviceCode">The device code identifying the authorization request to remove.</param>
    /// <param name="userCode">The user code of THAT request, used to find its secondary index entry.
    /// Nothing here checks the two belong together, so a caller passing a code from a different request
    /// removes that other request's index entry instead, leaving a live request findable only by its
    /// device code. The claim now returns the record, which carries the right user code, so this
    /// parameter has stopped being the only way to find the entry and is kept because the interface
    /// publishes it.</param>
    /// <returns>
    /// A task that completes when the operation finishes, containing true when this caller removed the
    /// request. False means the request was not there to remove: either another caller took it, or it
    /// expired, or it never existed.
    /// <para>
    /// The index cleanup that runs after the claim cannot change that answer either way. Removing the
    /// user-code index is a different question from whether this caller took the code, so a refusal is logged
    /// and the true stands. The entry left behind is the one the caller's own user code named, which need
    /// not be the removed request's, and it carries its own expiry either way.
    /// </para>
    /// </returns>
    public async Task<bool> TryRemoveAsync(string deviceCode, string userCode)
    {
        var claimed = await storage.GetAsync<DeviceAuthorizationRequest>(
            keyFactory.DeviceAuthorizationRequestKey(deviceCode),
            removeOnRetrieval: true);

        var removed = claimed != null;
        if (!removed)
            return false;

        // The device code is consumed at this point, and that is the fact the caller asked about. Tidying
        // the secondary index is a different question, so a store that refuses it does not get to take the
        // answer away: the token endpoint calls this inside a `when` clause, where an exception becomes a
        // server fault rather than a grant error - no tokens for a code that can never be presented again,
        // and the end user's approval lost with it.
        //
        // The entry left behind carries its own expiry, so it goes away unattended. Removing the index
        // FIRST instead would make the fault retryable, at the cost of a window in which the user code
        // resolves to nothing while the device code is still live - a worse trade, because that window is
        // on the path that succeeds.
        //
        // Swallowed, not hidden. Nothing else in the system reports a dangling index, so without this line
        // an operator has no way to learn the store refused a write at all.
        var deviceCodeKey = keyFactory.DeviceAuthorizationRequestKey(deviceCode);
        try
        {
            await storage.RemoveAsync(keyFactory.DeviceAuthorizationUserCodeKey(userCode));
        }
        catch (Exception exception)
        {
            // The DEVICE code key, not the user-code one. Nothing checks that the user code the caller
            // handed over belongs to the request just claimed, and on the public interface a host may
            // hand it a live one, so the key that was tried is not known to name this request. The device
            // code carries no such doubt: this line is reached only because the claim removed it.
            //
            // The claimed record carries the right user code and would settle that, which is a change to
            // what this method does with its argument rather than to how it reports a refusal.
            LogUserCodeIndexNotRemovedAfterClaim(exception, deviceCodeKey);
        }

        return true;
    }
}
