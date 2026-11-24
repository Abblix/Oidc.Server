// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The JSON object a fetched client metadata document is, or why it is none.
/// </summary>
internal static class MetadataDocumentJson
{
    /// <summary>
    /// The JSON object <paramref name="content"/> holds, every string of it decoding, or the terminal failure naming
    /// why it does not.
    /// </summary>
    /// <param name="content">The body of the response, as UTF-8 bytes.</param>
    public static Result<JsonObject, MetadataDocumentFailure> Parse(byte[] content)
    {
        JsonNode? document;
        try
        {
            // A member repeated is refused here rather than met by the first reading of it, which would throw
            document = JsonNode.Parse(content, documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException exception)
        {
            return MetadataDocumentFailure.Terminal($"the document is not valid JSON: {exception.Message}");
        }

        if (document is not JsonObject json)
            return MetadataDocumentFailure.Terminal("the document is not a JSON object");

        // A string escaping a lone surrogate parses but decodes to no string (RFC 8259 section 8.2), so it is refused
        // here, wherever it stands, rather than throwing at the first reading of its member
        try
        {
            _ = json.ToJsonString();
        }
        catch (InvalidOperationException exception)
        {
            return MetadataDocumentFailure.Terminal($"the document does not decode: {exception.Message}");
        }

        return json;
    }
}
