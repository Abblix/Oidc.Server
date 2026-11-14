// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;

namespace Abblix.Jwt;

/// <summary>
/// How a JOSE header or a JWT claims set is parsed.
/// </summary>
internal static class JoseJson
{
    /// <summary>
    /// Makes the parser itself reject a repeated member name, at any depth, which is the first of the two options
    /// RFC 7519 Section 4 and RFC 7515 Section 4 allow a recipient, and which RFC 7516 Section 4 extends to a JWE
    /// header "just as described in Section 4 of [JWS]". It reports the repetition as a <see cref="JsonException"/>
    /// at parse time, alongside every other malformed-JSON verdict.
    /// </summary>
    private static readonly JsonDocumentOptions RejectRepeatedMemberNames = new()
    {
        AllowDuplicateProperties = false,
    };

    /// <summary>
    /// Reads a decoded JOSE header or claims set as a JSON object, refusing anything else: octets that are not UTF-8,
    /// malformed JSON, a value that is not an object, a repeated member name.
    /// </summary>
    /// <remarks>
    /// RFC 7519 section 7.2 steps 4 and 10, and RFC 7515 and RFC 7516 section 5.2 step 3, have the recipient
    /// "Verify that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON
    /// object". The octets are checked as a whole: the JSON reader validates the encoding of a string value only
    /// when the value is read, and decoding to a string first would replace an invalid sequence and read on.
    /// </remarks>
    public static bool TryParseObject(byte[] utf8Json, [NotNullWhen(true)] out JsonObject? jsonObject)
    {
        if (!Utf8.IsValid(utf8Json))
        {
            jsonObject = null;
            return false;
        }

        try
        {
            jsonObject = JsonNode.Parse(utf8Json, documentOptions: RejectRepeatedMemberNames) as JsonObject;
        }
        catch (JsonException)
        {
            jsonObject = null;
        }
        return jsonObject is not null;
    }
}
