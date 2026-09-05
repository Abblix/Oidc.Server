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
