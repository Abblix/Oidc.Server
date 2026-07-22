// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a successful backchannel authentication response (CIBA Core §7.3). This record indicates that
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
        /// request (CIBA Core §7.3).</summary>
        public const string AuthenticationRequestId = "auth_req_id";

        /// <summary>The <c>expires_in</c> response parameter giving the lifetime of the request, in
        /// seconds.</summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>The <c>interval</c> response parameter giving the minimum polling interval the client
        /// should observe, in seconds.</summary>
        public const string Interval = "interval";
    }
}
