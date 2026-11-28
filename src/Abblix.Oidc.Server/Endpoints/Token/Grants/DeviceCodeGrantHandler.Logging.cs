// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class DeviceCodeGrantHandler
{
    /// <summary>
    /// The only account of a record that cannot be looked at afterwards.
    /// </summary>
    /// <remarks>
    /// The record is removed as it is refused, so a second poll answers as for a code the storage does not
    /// hold. Nothing else says what was wrong with it.
    ///
    /// Error rather than Warning, and it names the MEMBER rather than the status: nothing in this library
    /// writes a record in this shape, so it is a defect in code outside it that WRITES one, and the
    /// operator reading it needs to be sent to that writer rather than to the state machine. The message
    /// therefore leads with the calls a host makes, and names a replacement implementation only after
    /// them: this library ships and registers one, so a reader sent to the implementer FIRST would go
    /// looking for code they never wrote.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceCodeGrantHandler.AuthorizedRecordCarriesNoGrant,
        Level = LogLevel.Error,
        Message = "Client {ClientId} presented a device code whose stored record is marked authorized " +
                  "and carries no AuthorizedGrant, so there is nothing to issue and the redemption is " +
                  "refused. This library always sets the grant and the status together, so audit the " +
                  "code outside it that writes a device authorization record - a call to " +
                  "IDeviceAuthorizationStorage.UpdateAsync or StoreAsync, or a replacement registered " +
                  "for that interface.")]
    private partial void LogAuthorizedRecordCarriesNoGrant(string ClientId);
}
