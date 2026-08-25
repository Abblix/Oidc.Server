// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// The authorization-detail type identifier. RFC 9396 §2 makes it REQUIRED, and §2.1 governs
    /// what a value may be;
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
    public static class Parameters
    {
        /// <summary>The authorization detail type identifier, REQUIRED on every entry.</summary>
        public const string Type = "type";

        /// <summary>The locations of the resource servers the entry is addressed to.</summary>
        public const string Locations = "locations";

        /// <summary>The actions the entry authorises at those locations.</summary>
        public const string Actions = "actions";

        /// <summary>The kinds of data the entry authorises access to.</summary>
        public const string Datatypes = "datatypes";

        /// <summary>The identifier of the specific resource the entry is about.</summary>
        public const string Identifier = "identifier";

        /// <summary>The privileges the entry asks for at those locations.</summary>
        public const string Privileges = "privileges";
    }
}
