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

namespace Abblix.Jwt;

/// <summary>
/// One entry in the OAuth 2.0 Rich Authorization Requests <c>authorization_details</c> array
/// (RFC 9396 §2), wrapped over a <see cref="JsonNode"/> which is the source of truth for the
/// entry's content. The wrapper exposes the RFC 9396 §2.2 common-data members as strongly-typed
/// accessors that read from and write to the underlying <see cref="Json"/> directly - the same
/// shape <see cref="JsonWebTokenPayload"/> uses over its <see cref="JsonObject"/>.
/// </summary>
/// <param name="Json">The underlying JSON node carrying the entry's wire shape. Member order,
/// type-specific payload (RFC 9396 §2.2 extension members), and any unknown fields the AS does
/// not model survive the authorize → code → token round-trip byte-exact because no typed
/// deserialise / re-serialise cycle ever runs over them.</param>
/// <remarks>
/// Type-specific members outside the §2.2 common-data set (for example the
/// <c>instructedAmount</c> / <c>creditorAccount</c> fields of a PSD2 <c>payment_initiation</c>
/// entry) are accessed directly through <see cref="Json"/>; the per-type validator that owns
/// the schema for a given <c>type</c> reads and writes them via the
/// <see cref="System.Text.Json.Nodes"/> API on the wrapped node.
/// </remarks>
public record AuthorizationDetail(JsonObject Json)
{
    /// <summary>The underlying JSON node carrying the entry's wire shape. Member order,
    /// type-specific payload (RFC 9396 §2.2 extension members), and any unknown fields the AS does
    /// not model survive the authorize → code → token round-trip byte-exact because no typed
    /// deserialise / re-serialise cycle ever runs over them.</summary>
    public JsonObject Json { get; } = Json;

    /// <summary>
    /// The authorization-detail type identifier per RFC 9396 §2.1. Required by the spec;
    /// the per-type validator rejects entries where this member is missing with
    /// <c>invalid_authorization_details</c>.
    /// </summary>
    public string? Type
    {
        get => Json.GetProperty<string>(Parameters.Type);
        set => Json.SetProperty(Parameters.Type, value);
    }

    /// <summary>
    /// Locations of the resource server(s) the client wants to access, per RFC 9396 §2.2.
    /// Typically URIs identifying resource servers.
    /// </summary>
    public IEnumerable<string>? Locations
    {
        get => Json.GetArrayOfStringsOrNull(Parameters.Locations);
        set => Json.SetArrayOrStringOrNull(Parameters.Locations, value);
    }

    /// <summary>
    /// Kinds of actions to be taken at the resource, per RFC 9396 §2.2.
    /// </summary>
    public IEnumerable<string>? Actions
    {
        get => Json.GetArrayOfStringsOrNull(Parameters.Actions);
        set => Json.SetArrayOrStringOrNull(Parameters.Actions, value);
    }

    /// <summary>
    /// Kinds of data being requested from the resource, per RFC 9396 §2.2.
    /// </summary>
    public IEnumerable<string>? Datatypes
    {
        get => Json.GetArrayOfStringsOrNull(Parameters.Datatypes);
        set => Json.SetArrayOrStringOrNull(Parameters.Datatypes, value);
    }

    /// <summary>
    /// A specific resource identifier at the API, per RFC 9396 §2.2.
    /// </summary>
    public string? Identifier
    {
        get => Json.GetProperty<string>(Parameters.Identifier);
        set => Json.SetProperty(Parameters.Identifier, value);
    }

    /// <summary>
    /// Types or levels of privilege being requested at the resource, per RFC 9396 §2.2.
    /// </summary>
    public IEnumerable<string>? Privileges
    {
        get => Json.GetArrayOfStringsOrNull(Parameters.Privileges);
        set => Json.SetArrayOrStringOrNull(Parameters.Privileges, value);
    }

    /// <summary>
    /// RFC 9396 §2.2 member names. Type-specific members outside this set live alongside in
    /// <see cref="Json"/> and are accessed by per-type validators directly through the
    /// <see cref="System.Text.Json.Nodes"/> API on the wrapped node.
    /// </summary>
    private static class Parameters
    {
        public const string Type = "type";
        public const string Locations = "locations";
        public const string Actions = "actions";
        public const string Datatypes = "datatypes";
        public const string Identifier = "identifier";
        public const string Privileges = "privileges";
    }
}
