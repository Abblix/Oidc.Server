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
/// Keeps the question a session currently has outstanding in the server's entity storage, as a hash of the value
/// the end user's page will send back.
/// </summary>
/// <param name="storage">Where the outstanding question is kept.</param>
/// <param name="keyFactory">Names the storage key a session's question is kept under.</param>
/// <param name="options">Source of the value's length and of how long a question stays good for.</param>
public sealed class LogoutConfirmationStore(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    IOptions<OidcOptions> options) : ILogoutConfirmationStore
{
    /// <inheritdoc />
    public async Task<string> IssueAsync(string sessionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        // Drawn from a cryptographically secure source and sized by configuration, like every other value this
        // server issues that an outsider must not be able to state: guessing one would end a session.
        var confirmation = Base64Url.EncodeToString(
            CryptoRandom.GetRandomBytes(options.Value.LogoutConfirmationLength));

        // One record per session, replacing whatever question was outstanding. Asking is something any site can
        // cause, so a record per request would let an outsider fill the store with questions nobody will answer;
        // and a session has one end user, who is looking at one page. The record holds a hash, so nothing in the
        // store is an answer somebody could send.
        await storage.SetAsync(
            keyFactory.LogoutConfirmationKey(sessionId),
            new LogoutConfirmation { ConfirmationHash = HashOf(confirmation) },
            new StorageOptions { AbsoluteExpirationRelativeToNow = options.Value.LogoutConfirmationLifetime });

        return confirmation;
    }

    /// <inheritdoc />
    public async Task<bool> RedeemLogoutConfirmationAsync(string sessionId, string confirmation)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        var outstanding = await storage.GetAsync<LogoutConfirmation>(
            keyFactory.LogoutConfirmationKey(sessionId),
            removeOnRetrieval: false);

        if (outstanding == null || !Matches(outstanding.ConfirmationHash, confirmation))
            return false;

        // Removed only once the answer is the one this session was asked for, so a value somebody else sends
        // cannot spend the question the end user is looking at. Two answers racing both end the same session,
        // which is what the request asked for either way.
        await storage.RemoveAsync(keyFactory.LogoutConfirmationKey(sessionId));
        return true;
    }

    /// <summary>
    /// Compares the presented value against the hash the session's question was stored as, in time that does not
    /// depend on how much of it matches.
    /// </summary>
    private static bool Matches(string outstandingHash, string confirmation)
        => CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(outstandingHash),
            Encoding.UTF8.GetBytes(HashOf(confirmation)));

    /// <summary>
    /// Hashes the value, so what the store holds is a question rather than an answer.
    /// </summary>
    private static string HashOf(string confirmation)
        => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(confirmation)));
}
