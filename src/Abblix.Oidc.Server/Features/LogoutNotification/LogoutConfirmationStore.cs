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
/// Keeps the question a session currently has outstanding in the server's entity storage, under the session's own
/// key, so that asking again is the same question rather than another one.
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

        var key = keyFactory.LogoutConfirmationKey(sessionId);

        // Asking again is the same question. Anyone can make a browser reach the logout address, so issuing a
        // value per request would do two things at once: fill the store with questions nobody will answer, and
        // let a request arriving while the end user reads the page void the answer they are about to give.
        if (await storage.GetAsync<LogoutConfirmation>(key, removeOnRetrieval: false) is { } outstanding)
            return outstanding.Confirmation;

        // Drawn from a cryptographically secure source and sized by configuration, like every other value this
        // server issues that an outsider must not be able to state: guessing one would end a session.
        var confirmation = Base64Url.EncodeToString(
            CryptoRandom.GetRandomBytes(options.Value.LogoutConfirmationLength));

        await storage.SetAsync(
            key,
            new LogoutConfirmation { Confirmation = confirmation },
            new StorageOptions { AbsoluteExpirationRelativeToNow = options.Value.LogoutConfirmationLifetime });

        return confirmation;
    }

    /// <inheritdoc />
    public async Task<bool> RedeemLogoutConfirmationAsync(string sessionId, string confirmation)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        var key = keyFactory.LogoutConfirmationKey(sessionId);
        var outstanding = await storage.GetAsync<LogoutConfirmation>(key, removeOnRetrieval: false);

        if (outstanding == null || !Matches(outstanding.Confirmation, confirmation))
            return false;

        // Removed only once the answer is the one this session was asked with, so a wrong value somebody else
        // sends cannot spend the question the end user is looking at. Read and removal are two calls rather than
        // one, so two identical answers arriving together can both be told they took it; they end the same
        // session, which is what each of them asked for.
        await storage.RemoveAsync(key);
        return true;
    }

    /// <summary>
    /// Compares the presented value with the one this session was asked with, in time that does not depend on how
    /// much of it matches, because the caller chooses the value being compared.
    /// </summary>
    private static bool Matches(string outstanding, string confirmation)
        => CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(outstanding),
            Encoding.UTF8.GetBytes(confirmation));
}
