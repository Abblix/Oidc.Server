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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Jwt;

/// <summary>
/// One entry in the OAuth 2.0 Rich Authorization Requests <c>authorization_details</c> array
/// (RFC 9396 §2). Carries the required <see cref="Type"/> discriminator plus the optional
/// common data fields from RFC 9396 §2.2; any additional type-specific members land in
/// <see cref="ExtensionData"/> and round-trip losslessly.
/// </summary>
/// <remarks>
/// The <see cref="Type"/> member is the dispatch key the per-type validator registry uses to
/// route each entry to the matching handler (slice #131). The common data fields
/// (<see cref="Locations"/>, <see cref="Actions"/>, <see cref="Datatypes"/>,
/// <see cref="Identifier"/>, <see cref="Privileges"/>) carry the semantics defined in
/// RFC 9396 §2.2 when the host's per-type schema chooses to use them; alternative or
/// additional fields are preserved in <see cref="ExtensionData"/>.
/// </remarks>
public record AuthorizationDetail
{
    /// <summary>
    /// The authorization-detail type identifier per RFC 9396 §2.1. Required by the spec; the
    /// per-type validator (slice #131) rejects entries where this member is missing with
    /// <c>invalid_authorization_details</c>.
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = default!;

    /// <summary>
    /// Locations of the resource server(s) the client wants to access, per RFC 9396 §2.2.
    /// Typically URIs identifying resource servers.
    /// </summary>
    [JsonPropertyName("locations")]
    public string[]? Locations { get; init; }

    /// <summary>
    /// Kinds of actions to be taken at the resource, per RFC 9396 §2.2.
    /// </summary>
    [JsonPropertyName("actions")]
    public string[]? Actions { get; init; }

    /// <summary>
    /// Kinds of data being requested from the resource, per RFC 9396 §2.2.
    /// </summary>
    [JsonPropertyName("datatypes")]
    public string[]? Datatypes { get; init; }

    /// <summary>
    /// A specific resource identifier at the API, per RFC 9396 §2.2.
    /// </summary>
    [JsonPropertyName("identifier")]
    public string? Identifier { get; init; }

    /// <summary>
    /// Types or levels of privilege being requested at the resource, per RFC 9396 §2.2.
    /// </summary>
    [JsonPropertyName("privileges")]
    public string[]? Privileges { get; init; }

    /// <summary>
    /// Type-specific members outside the RFC 9396 §2.2 common-data set. Preserved across
    /// JSON round-trip so the per-type validator registered for <see cref="Type"/> sees the
    /// original payload verbatim.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; init; }
}
