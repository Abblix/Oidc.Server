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

using System.Text.Json.Nodes;
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
    /// RFC 9396 §3 Rich Authorization Requests array stored as the raw wire
    /// <see cref="JsonArray"/>. Device flows accept <c>authorization_details</c> by spec
    /// reference (RFC 9396 §3 cites RFC 8628); the array carries through to the eventual
    /// access token issued via the device-code grant byte-exact.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationDetails)]
    public JsonArray? AuthorizationDetails { get; init; }

    /// <summary>
    /// Contains constants representing the parameter names used in the device authorization request.
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>scope</c> device authorization request parameter listing requested scopes
        /// (RFC 8628 §3.1).</summary>
        public const string Scope = "scope";

        /// <summary>The <c>resource</c> device authorization request parameter (RFC 8707) targeting a
        /// specific protected resource for the resulting tokens.</summary>
        public const string Resource = "resource";

        /// <summary>The <c>authorization_details</c> device authorization request parameter
        /// (RFC 9396 §3) carrying a JSON array of Rich Authorization Requests.</summary>
        public const string AuthorizationDetails = "authorization_details";
    }
}
