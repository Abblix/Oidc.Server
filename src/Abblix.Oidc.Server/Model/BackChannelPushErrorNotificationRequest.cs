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
/// The error payload a push-mode client receives at its notification endpoint when its request ends without
/// tokens (OpenID Connect CIBA Core 1.0 section 12).
/// </summary>
/// <remarks>
/// A push-mode client never comes to the token endpoint, so this is the only way it learns that the end user
/// refused, that the server refused the answer, or that the transaction failed; without it the client waits
/// for the request to expire.
/// </remarks>
public sealed record BackChannelPushErrorNotificationRequest : IBackChannelNotificationRequest
{
    /// <summary>
    /// The authentication request identifier the error is about.
    /// </summary>
    [JsonPropertyName(Parameters.AuthReqId)]
    public required string AuthenticationRequestId { get; init; }

    /// <summary>
    /// One of the three codes section 12 allows here: <c>access_denied</c>, <c>expired_token</c> or
    /// <c>transaction_failed</c>.
    /// </summary>
    [JsonPropertyName(Parameters.Error)]
    public required string Error { get; init; }

    /// <summary>
    /// Text for the client developer. Section 12 limits it to printable ASCII without the double quote and the
    /// backslash.
    /// </summary>
    [JsonPropertyName(Parameters.ErrorDescription)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Wire-level parameter names of the push error payload (OpenID Connect CIBA Core 1.0 section 12).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>auth_req_id</c> parameter naming the request the error is about.</summary>
        public const string AuthReqId = "auth_req_id";

        /// <summary>The <c>error</c> parameter carrying the error code.</summary>
        public const string Error = "error";

        /// <summary>The <c>error_description</c> parameter carrying text for the client developer.</summary>
        public const string ErrorDescription = "error_description";
    }
}
