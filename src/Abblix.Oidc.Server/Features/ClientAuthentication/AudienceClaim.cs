// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Reads the audience claim of a client assertion as written, a string or an array of strings, so a value of another
/// kind refuses the claim rather than being stepped over.
/// </summary>
internal static class AudienceClaim
{
    /// <summary>
    /// Answers whether the audience claim names a value <paramref name="accepts"/> takes, as a string, or, when
    /// <paramref name="allowArray"/>, in an array of strings beside others.
    /// </summary>
    /// <remarks>
    /// An array is still an array of strings, as RFC 7519 section 4.1.3 has it: a member of another kind refuses the
    /// claim rather than being stepped over.
    /// </remarks>
    /// <param name="audience">The audience claim as written.</param>
    /// <param name="allowArray">Whether the claim may be an array.</param>
    /// <param name="accepts">Whether a value is one the caller accepts.</param>
    public static bool Names(JsonNode? audience, bool allowArray, Func<string, bool> accepts) => audience switch
    {
        JsonValue value => AsString(value) is { } written && accepts(written),
        JsonArray array when allowArray => array.Select(AsString).ToArray() is var members &&
                                           members.All(member => member is not null) &&
                                           members.Any(member => accepts(member!)),
        _ => false,
    };

    private static string? AsString(JsonNode? node)
        => node is JsonValue value && value.TryGetValue<string>(out var written) ? written : null;
}
