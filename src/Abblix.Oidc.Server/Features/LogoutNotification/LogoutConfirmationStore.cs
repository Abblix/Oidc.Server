// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Storages.Proto;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Keeps each issued logout confirmation in the server's entity storage, under the value itself, until it is
/// redeemed or expires.
/// </summary>
/// <param name="storage">Where the issued confirmations are kept.</param>
/// <param name="keyFactory">Names the storage key a confirmation is kept under.</param>
/// <param name="options">Source of the confirmation's length and lifetime.</param>
public sealed class LogoutConfirmationStore(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options) : ILogoutConfirmationStore
{
    /// <inheritdoc />
    public async Task<string> IssueAsync(string sessionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        // One outstanding question per session. Asking is something any site can cause, by making the browser
        // fetch the logout address with its cookie on it, so issuing a value per request would let an outsider
        // fill the store with entries nobody will ever answer. Re-using the live one costs that attack nothing
        // to keep going and costs the store one entry per session either way, and the end user sees the same
        // question whichever request rendered it.
        var sessionKey = keyFactory.LogoutConfirmationForSessionKey(sessionId);
        if (await storage.GetAsync<string>(sessionKey, removeOnRetrieval: false) is { } outstanding)
            return outstanding;

        // Drawn from a cryptographically secure source and sized by configuration, like every other value this
        // server issues that an outsider must not be able to state: guessing one would end a session.
        var confirmation = Base64Url.EncodeToString(
            CryptoRandom.GetRandomBytes(options.Value.LogoutConfirmationLength));

        var expiry = new StorageOptions
        {
            AbsoluteExpirationRelativeToNow = options.Value.LogoutConfirmationLifetime,
        };

        await storage.SetAsync(KeyOf(confirmation), new LogoutConfirmation { SessionId = sessionId }, expiry);

        // The value itself, so the next question can hand back the one already asked. It is a value rather than
        // a key, which is the side of the store that carries secrets.
        await storage.SetAsync(sessionKey, confirmation, expiry);

        return confirmation;
    }

    /// <inheritdoc />
    public async Task<string?> RedeemLogoutConfirmationAsync(string confirmation)
    {
        // Removed as it is read, so an answer spent on one logout cannot be replayed against the session the end
        // user signs into next. The take-once protocol tells this caller it took the value only when the protocol
        // ran to the end and its own claim was still in the store, so a refusal covers the value not being there,
        // another caller having taken it, and a claim that expired mid-protocol - and every one of them ends in
        // the end user being asked again.
        var issued = await storage.GetAsync<LogoutConfirmation>(KeyOf(confirmation), removeOnRetrieval: true);
        if (issued == null)
            return null;

        // The question has been answered, so the next one starts afresh rather than handing back a value that
        // is already spent and would be refused.
        await storage.RemoveAsync(keyFactory.LogoutConfirmationForSessionKey(issued.SessionId));

        return issued.SessionId;
    }

    /// <summary>
    /// Names the key a confirmation is kept under, from a hash of it rather than from the value: the value is a
    /// secret, and a store's keys travel into logs and administration tools that its values do not.
    /// </summary>
    private string KeyOf(string confirmation)
        => keyFactory.LogoutConfirmationKey(
            Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(confirmation))));
}
