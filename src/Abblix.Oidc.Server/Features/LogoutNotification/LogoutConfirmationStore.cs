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
using Abblix.Oidc.Server.Features.MultiTenancy;
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
    public async Task<string> IssueAsync(TenantDefinition tenant, string sessionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        var key = keyFactory.LogoutConfirmationKey(tenant, sessionId);

        // Asking again is the same question. Anyone can make a browser reach the logout address, so issuing a
        // fresh value here would let a request arriving while the end user reads the page void the answer they
        // are about to give. A value is written only where the session has none, and the storage decides that
        // between concurrent callers: of two first requests that overlap, one writes and the other reads back what
        // it wrote. The default storage decides within one process only; across nodes that takes a storage built on
        // the store's own set-if-absent. A value answered or expired between that losing write and the read leaves the session with no
        // question, and the next pass asks afresh.
        for (var attempt = 0; attempt < IssuingAttempts; attempt++)
        {
            if (await storage.GetAsync<LogoutConfirmation>(key, removeOnRetrieval: false) is { } outstanding)
                return outstanding.Confirmation;

            // Drawn from a cryptographically secure source and sized by configuration, like every other value this
            // server issues that an outsider must not be able to state: guessing one would end a session.
            var confirmation = Base64Url.EncodeToString(
                CryptoRandom.GetRandomBytes(options.Value.LogoutConfirmationLength));

            if (await storage.TrySetIfAbsentAsync(
                    key,
                    new LogoutConfirmation { Confirmation = confirmation },
                    new StorageOptions { AbsoluteExpirationRelativeToNow = options.Value.LogoutConfirmationLifetime }))
            {
                return confirmation;
            }
        }

        throw new InvalidOperationException(
            $"The logout confirmation could not be issued: on each of {IssuingAttempts} attempts the storage " +
            "reported a value already written and then read none, as a storage whose write still counts an expired " +
            "entry while its read no longer returns it does");
    }

    /// <summary>
    /// How many times a question is read and written before giving up. Each pass that writes nothing has lost to
    /// another request of the same session, so a few are enough; a storage whose write still counts an expired entry
    /// while its read no longer returns it would otherwise keep the request, and a thread, busy for good.
    /// </summary>
    private const int IssuingAttempts = 16;

    /// <inheritdoc />
    public async Task<bool> RedeemLogoutConfirmationAsync(TenantDefinition tenant, string sessionId, string confirmation)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        // Nothing is what an empty value answers. Two empty spans compare equal, so a record that somehow holds
        // no value would otherwise be answered by a request carrying the parameter and nothing in it.
        if (confirmation.Length == 0)
            return false;

        var key = keyFactory.LogoutConfirmationKey(tenant, sessionId);
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
