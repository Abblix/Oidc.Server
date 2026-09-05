// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.E2E.Tests;

internal static class QueryHelpers
{
    public static Uri BuildUri(Uri baseUri, IEnumerable<KeyValuePair<string, string>> queryParams)
    {
        var builder = new UriBuilder(baseUri);
        var query = string.Join('&', queryParams
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        builder.Query = string.IsNullOrEmpty(builder.Query)
            ? query
            : builder.Query.TrimStart('?') + "&" + query;
        return builder.Uri;
    }
}