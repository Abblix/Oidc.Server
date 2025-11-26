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

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents the response to a pushed authorization request. This response includes the URI
/// where the authorization request is stored and the duration for which the request will remain valid.
/// </summary>
public record PushedAuthorizationResponse
{
    /// <summary>
    /// Defines constant parameter names used in the response.
    /// </summary>
    public static class Parameters {
        /// <summary>
        /// The parameter name for the request URI in the response.
        /// </summary>
        public const string  RequestUri = "request_uri";

        /// <summary>
        /// The parameter name for the expiration duration of the stored request.
        /// </summary>
        public const string  ExpiresIn = "expires_in";
    }

    /// <summary>
    /// The URI where the authorization request is stored.
    /// This URI is used by the client to refer to the authorization request in subsequent operations.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUri)]
    [JsonPropertyOrder(1)]
    public Uri RequestUri { get; init; } = null!;

    /// <summary>
    /// The duration for which the authorization request is considered valid.
    /// After this period, the request may no longer be retrievable or usable.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonPropertyOrder(2)]
    public TimeSpan ExpiresIn { get; init; }
}
