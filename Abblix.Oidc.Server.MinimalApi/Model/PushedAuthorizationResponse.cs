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

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// The response to a pushed authorization request (RFC 9126): the request URI the client refers to on the
/// authorization endpoint, and how long it stays valid.
/// </summary>
public record PushedAuthorizationResponse
{
    private static class Parameters
    {
        public const string RequestUri = "request_uri";
        public const string ExpiresIn = "expires_in";
    }

    /// <summary>The URI where the pushed authorization request is stored.</summary>
    [JsonPropertyName(Parameters.RequestUri)]
    [JsonPropertyOrder(1)]
    public Uri RequestUri { get; init; } = null!;

    /// <summary>How long the stored request stays valid.</summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonPropertyOrder(2)]
    public TimeSpan ExpiresIn { get; init; }
}
