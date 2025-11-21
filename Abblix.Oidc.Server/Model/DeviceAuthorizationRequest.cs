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
/// Represents a device authorization request as defined in RFC 8628.
/// This request is initiated by a device with limited input capabilities to obtain
/// a device code and user code for user authentication on a separate device.
/// </summary>
public record DeviceAuthorizationRequest
{
    /// <summary>
    /// A space-separated list of scopes requested by the client.
    /// Scopes define the level of access requested and the types of information
    /// the client wants to retrieve.
    /// </summary>
    [JsonPropertyName(Parameters.Scope)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? Scope { get; init; }

    /// <summary>
    /// Specifies the resource for which the access token is requested.
    /// As defined in RFC 8707, this parameter requests access tokens with a specific
    /// scope for a particular resource.
    /// </summary>
    [JsonPropertyName(Parameters.Resource)]
    [JsonConverter(typeof(SingleOrArrayConverter<Uri>))]
    public Uri[]? Resources { get; init; }

    /// <summary>
    /// Contains constants representing the parameter names used in the device authorization request.
    /// </summary>
    public static class Parameters
    {
        public const string Scope = "scope";
        public const string Resource = "resource";
    }
}
