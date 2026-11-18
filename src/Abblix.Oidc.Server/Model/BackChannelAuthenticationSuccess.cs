// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a successful backchannel authentication response (CIBA Core section 7.3). This record indicates that
/// the backchannel authentication request has been accepted and end-user authentication is now pending;
/// the issued <c>auth_req_id</c> identifies the pending request.
/// </summary>
public record BackChannelAuthenticationSuccess
{
    /// <summary>
    /// The unique identifier of the authentication request. The client uses this ID
    /// to poll the authorization server and check the status of the user's authentication.
    /// </summary>
    [JsonPropertyName(Parameters.AuthenticationRequestId)]
    public required string AuthenticationRequestId { get; set; }

    /// <summary>
    /// Specifies the time period (in seconds) after which the backchannel authentication request expires.
    /// After this duration, the authentication request is no longer valid, and the client will need
    /// to initiate a new request if authentication has not been completed.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan ExpiresIn { get; set; }

    /// <summary>
    /// The interval (in seconds) that the client should use when polling the authorization server
    /// to check the status of the authentication. This prevents excessive polling and ensures
    /// that the client follows the recommended polling rate.
    /// </summary>
    [JsonPropertyName(Parameters.Interval)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan Interval { get; set; }

    /// <summary>
    /// Contains constants representing the parameter names used in the backchannel authentication response.
    /// These are included in the JSON response to the client to ensure the correct values are returned.
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>auth_req_id</c> response parameter identifying the backchannel authentication
        /// request (CIBA Core section 7.3).</summary>
        public const string AuthenticationRequestId = "auth_req_id";

        /// <summary>The <c>expires_in</c> response parameter giving the lifetime of the request, in
        /// seconds.</summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>The <c>interval</c> response parameter giving the minimum polling interval the client
        /// should observe, in seconds.</summary>
        public const string Interval = "interval";
    }
}
