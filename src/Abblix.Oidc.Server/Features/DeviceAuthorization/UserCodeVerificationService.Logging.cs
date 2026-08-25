// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

partial class UserCodeVerificationService
{
    /// <summary>
    /// The count and the client, never the entries themselves: an authorization_details entry carries
    /// whatever its type defines, which for the types this exists to serve is payment and account data.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeVerificationService.GrantedAuthorizationDetailsNotCarried,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} requested {RequestedCount} authorization_details entries at the device " +
                  "endpoint, and the approved grant carries none. The user-verification page decides what it " +
                  "shows and what it grants, so the library leaves the entries to it (see ValidUserCode); a " +
                  "grant without them issues a token no resource server can enforce against (RFC 9396 §9).")]
    private partial void LogGrantedAuthorizationDetailsNotCarried(string ClientId, int RequestedCount);

    /// <summary>
    /// The escaped TYPES only, for the same reason: what a type carries is its own business, and here it
    /// is payment and account data.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.Device.UserCodeVerificationService.GrantedAuthorizationDetailsExceedTheRequest,
        Level = LogLevel.Warning,
        Message = "Client {ClientId} was approved with authorization_details the device authorization " +
                  "request never asked for, so the approval is refused: {EscapedTypes}")]
    private partial void LogGrantedAuthorizationDetailsExceedTheRequest(string ClientId, string EscapedTypes);
}
