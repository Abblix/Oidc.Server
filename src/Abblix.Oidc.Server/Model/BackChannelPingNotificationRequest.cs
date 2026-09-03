// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the notification payload sent to the client in ping mode.
/// </summary>
public sealed record BackChannelPingNotificationRequest : IBackChannelNotificationRequest
{
    /// <summary>
    /// The authentication request identifier that is ready for token retrieval.
    /// </summary>
    [JsonPropertyName(Parameters.AuthReqId)]
    public required string AuthenticationRequestId { get; init; }

    /// <summary>
    /// Wire-level parameter names for the CIBA ping-mode notification payload
    /// (OpenID Connect CIBA Core 1.0 section 10.2).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>auth_req_id</c> notification parameter identifying the CIBA request that is
        /// now ready for token retrieval.</summary>
        public const string AuthReqId = "auth_req_id";
    }
}
