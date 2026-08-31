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
    /// It names the DEVICE code key and not the user-code one, which is the opposite of the sibling
    /// below, and the difference is where each method gets the code from. There the user code is read
    /// out of the stored record, so it belongs to the request being removed. Here it arrives as a
    /// PARAMETER and nothing checks the two belong together - <c>TryRemoveAsync</c> never reads the
    /// record - so on the public interface a host can hand this method a live code belonging to some
    /// other request, and the key that embeds it would be written to a log in full while it is still
    /// redeemable. The device code carries no such doubt: this line is only reached because the claim
    /// removed it.
    /// <para>
    /// The entry cannot be named exactly as a result. That costs less than it looks: the action this
    /// line asks for is never "delete that key" - the entry expires on its own - it is "the store
    /// refused a write". Warning rather than error, because the caller was answered and nothing
    /// downstream is waiting.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedAfterClaim,
        Level = LogLevel.Warning,
        Message = "The device code at {DeviceCodeKey} was claimed and removed, but the store refused to " +
                  "remove the user-code index entry it was handed. That entry expires on its own; the " +
                  "caller was told it took the code, which it did. The entry is not named here because " +
                  "this method cannot establish that the user code it was handed is the spent one - " +
                  "which is the same reason nothing here can say what that entry still points at.")]
    private partial void LogUserCodeIndexNotRemovedAfterClaim(Exception exception, string DeviceCodeKey);

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
    /// The code it names is dead at both shipped call sites - the record is expired or denied, and such a
    /// record cannot be carried to a decision: <c>ApproveAsync</c> and <c>DenyAsync</c> refuse anything not
    /// pending, and each refuses an expired record besides. <c>VerifyAsync</c> reads the status alone, so
    /// an expired-but-pending record still gets an answer there; it just cannot go further than that
    /// answer. This method is on the public
    /// interface though, so a host calling it with a live record logs a live code; that is the host's
    /// choice, and it is why the sibling's blanket "the code is spent" does not appear here.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemovedBeforeDiscard,
        Level = LogLevel.Warning,
        Message = "A device authorization request is being discarded, and its user-code index at " +
                  "{UserCodeKey} could not be removed. Nothing was issued and no caller was told it took " +
                  "the code. Removing the request itself runs next and is NOT guarded, so whether the " +
                  "caller sees a fault or a grant error depends on whether that write is refused too; " +
                  "the index entry expires on its own either way.")]
    private partial void LogUserCodeIndexNotRemovedBeforeDiscard(Exception exception, string UserCodeKey);
}
