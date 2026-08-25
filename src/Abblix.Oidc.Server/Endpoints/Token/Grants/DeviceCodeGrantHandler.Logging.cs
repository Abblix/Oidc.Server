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
    /// The escaped TYPES only, matching the approval-side record: what a type carries is its own business,
    /// and here it is payment and account data.
    /// </summary>
    /// <remarks>
    /// The refusal an operator has the least other evidence for. Its premise is that the stored grant
    /// changed after approval, so the warning the approval path writes cannot have fired, and the client
    /// sees an <c>access_denied</c> that says nothing about which type escaped.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceCodeGrantHandler.GrantedAuthorizationDetailsExceedTheRequest,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} redeemed a device code whose stored grant carries " +
                  "authorization_details types the device authorization request never asked for: " +
                  "{EscapedTypes}. The approval " +
                  "refuses this, so the grant was written to storage after it (RFC 9396 §6.1 defines no " +
                  "universal comparator, so the check is by type).")]
    private partial void LogGrantedAuthorizationDetailsExceedTheRequest(string ClientId, string EscapedTypes);
}
