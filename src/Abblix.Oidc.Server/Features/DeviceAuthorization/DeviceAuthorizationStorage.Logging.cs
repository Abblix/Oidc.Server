// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

partial class DeviceAuthorizationStorage
{
    /// <summary>
    /// The index survived a CLAIM: the device code is consumed and its caller was told so.
    /// </summary>
    /// <remarks>
    /// The key is named because it is what an operator would search for or delete. It EMBEDS the user
    /// code - the factory builds it by interpolation - so this line writes the code in full. That is
    /// acceptable HERE and only here: the claim has already removed the request, so the code cannot be
    /// verified or redeemed by the time this runs. Warning rather than error, because the caller was
    /// answered and nothing downstream is waiting.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedAfterClaim,
        Level = LogLevel.Warning,
        Message = "The device code was claimed and removed, but its user-code index at {UserCodeKey} " +
                  "could not be. The entry now points at a request that is gone, and it expires on its " +
                  "own; the caller was told it took the code, which it did.")]
    private partial void LogUserCodeIndexNotRemovedAfterClaim(Exception exception, string UserCodeKey);

    /// <summary>
    /// The index survived a DISCARD, where nothing was consumed and the request is still being removed.
    /// </summary>
    /// <remarks>
    /// A separate id from its sibling because the two say different things to whoever reads them. Here
    /// the record is expired or denied, no token was issued, nobody was told they took anything, and the
    /// request removal has not run yet - so a message borrowed from the claim path would send an operator
    /// looking for an issuance that never happened. One message true of both sites could only be one that
    /// neither could act on.
    /// <para>
    /// The code it names is dead at both shipped call sites - the record is expired or denied, and every
    /// entry point refuses a record that is not pending and unexpired. This method is on the public
    /// interface though, so a host calling it with a live record logs a live code; that is the host's
    /// choice, and it is why the sibling's blanket "the code is spent" does not appear here.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedBeforeDiscard,
        Level = LogLevel.Warning,
        Message = "A device authorization request is being discarded, and its user-code index at " +
                  "{UserCodeKey} could not be removed. Nothing was issued and no caller was told it took " +
                  "the code. Removing the request runs next and is NOT guarded, so a store refusing writes " +
                  "fails there too and the caller sees THAT fault rather than this line; the index entry " +
                  "expires on its own either way.")]
    private partial void LogUserCodeIndexNotRemovedBeforeDiscard(Exception exception, string UserCodeKey);
}
