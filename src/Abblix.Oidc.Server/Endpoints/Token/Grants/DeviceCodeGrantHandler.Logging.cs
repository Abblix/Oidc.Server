// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class DeviceCodeGrantHandler
{
    /// <summary>
    /// The escaped TYPES only, matching the approval-side record: what an entry of a type carries is that
    /// type's own business, and naming it here would put a deployment's data in a log line.
    /// </summary>
    /// <remarks>
    /// The refusal an operator has the least other evidence for: the approval path refuses the same shape,
    /// so its warning cannot have fired on this record, and the client sees an <c>access_denied</c> that
    /// says nothing about which type escaped.
    ///
    /// The message states what was observed and what was done, and stops there. What it must NOT say is
    /// which write produced the mismatch: the baseline and the grant live in the same host-owned record,
    /// so narrowing the baseline reads identically to widening the grant, and a host may have replaced
    /// <see cref="Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces.IUserCodeVerificationService"/>
    /// so that no approval ran at all. Naming a cause the gate cannot establish sends an operator looking
    /// for a write that never happened.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceCodeGrantHandler.GrantedAuthorizationDetailsExceedTheRequest,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} presented a device code whose stored grant carries " +
                  "authorization_details types the device authorization request never asked for, so the " +
                  "redemption is refused and no token was issued. Types: {EscapedTypes}. The comparison " +
                  "is by type, because RFC 9396 §6.1 defines no universal comparator for two arbitrary " +
                  "entries.")]
    private partial void LogGrantedAuthorizationDetailsExceedTheRequest(string ClientId, string EscapedTypes);

    /// <summary>
    /// The per-type validator's own words, which the client never sees.
    /// </summary>
    /// <remarks>
    /// A granted-phase rejection names a host-side defect, so the validator writes for whoever has to fix
    /// it and may name a tenant, a ceiling or a configuration key. The client is told only that the
    /// deployment will not issue these details; this is where the sentence that explains it lives.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceCodeGrantHandler.GrantedAuthorizationDetailsRefused,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} presented a device code whose stored grant the per-type validators " +
                  "will not issue, so the redemption is refused and no token was issued: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsRefused(string ClientId, string Reason);

    /// <summary>
    /// The only account of a record that cannot be looked at afterwards.
    /// </summary>
    /// <remarks>
    /// The device code is claimed before anything is judged, so by the time this fires the record is gone
    /// and a second poll answers expired_token. Nothing else says what was wrong with it.
    ///
    /// Error rather than Warning, and it names the MEMBER rather than the status: nothing in this library
    /// writes a record in this shape, so it is a defect in code outside it that WRITES one, and the
    /// operator reading it needs to be sent to that writer rather than to the state machine. Not to
    /// whoever implements the storage - this library ships and registers an implementation, so in a
    /// default deployment that reader would be sent to look for code they never wrote.
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
