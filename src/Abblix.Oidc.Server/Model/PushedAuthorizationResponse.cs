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
/// The wire response to a pushed authorization request (RFC 9126): the request URI the client refers to on the
/// authorization endpoint, and how long it stays valid. This is the framework-neutral wire projection both transport
/// adapters serialize. It is distinct from the domain result
/// <see cref="Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse"/>, which also
/// carries the stored authorization request; the formatter maps that domain result onto this flat wire shape.
/// </summary>
public record PushedAuthorizationResponse
{
    private static class Parameters
    {
        public const string RequestUri = "request_uri";
        public const string ExpiresIn = "expires_in";
    }

    /// <summary>
    /// The URI where the pushed authorization request is stored.
    /// RFC 9126 section 2.2 states no REQUIRED marker for this member and instead says the server MUST
    /// generate a request URI and provide it in the response, which binds just as tightly.
    /// </summary>
    [JsonPropertyName(Parameters.RequestUri)]
    [JsonPropertyOrder(1)]
    public required Uri RequestUri { get; init; }

    /// <summary>How long the stored request stays valid.</summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonPropertyOrder(2)]
    public TimeSpan ExpiresIn { get; init; }
}
