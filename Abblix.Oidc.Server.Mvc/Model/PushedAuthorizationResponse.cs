// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
//
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
//
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
//
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
//
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
//
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
//
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    public Uri RequestUri { get; init; } = default!;

    /// <summary>
    /// The duration for which the authorization request is considered valid.
    /// After this period, the request may no longer be retrievable or usable.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonPropertyOrder(2)]
    public TimeSpan ExpiresIn { get; init; }
}
