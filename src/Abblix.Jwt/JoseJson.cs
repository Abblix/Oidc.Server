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
    /// Reads a decoded JOSE header or claims set as a JSON object, refusing anything else: octets that are not
    /// Unicode text, malformed JSON, a value that is not an object, a repeated member name.
    /// </summary>
    /// <remarks>
    /// RFC 7519 section 7.2 steps 4 and 10, and RFC 7515 section 5.2 step 3, have the recipient "Verify that the
    /// resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object", as RFC 7516
    /// section 5.2 step 3 does for the protected header of a JWE.
    /// </remarks>
    public static bool TryParseObject(byte[] utf8Json, [NotNullWhen(true)] out JsonObject? jsonObject)
    {
        if (!IsUnicodeText(utf8Json))
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

    /// <summary>
    /// Whether <paramref name="utf8Json"/> is UTF-8 and every member name and string in it reads as Unicode text.
    /// </summary>
    /// <remarks>
    /// The JSON reader checks the encoding of a string only when the string is read, and an escape naming half of a
    /// surrogate pair passes every check until then, so a document that parses can still throw from the first value
    /// a caller reads. Every name and string is read here once, so such a document is refused where it arrives;
    /// malformed JSON is left for the parser to refuse.
    /// </remarks>
    public static bool IsUnicodeText(ReadOnlySpan<byte> utf8Json)
    {
        if (!Utf8.IsValid(utf8Json))
            return false;

        var reader = new Utf8JsonReader(utf8Json);
        try
        {
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName or JsonTokenType.String)
                    reader.GetString();
            }
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (JsonException)
        {
            // Malformed JSON, which the parser refuses in its own terms
        }

        return true;
    }
}
