// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Defines a contract for securely fetching content from external URIs with SSRF protection.
/// </summary>
public interface ISecureHttpFetcher
{
    /// <summary>
    /// Fetches content from a URI with SSRF protection.
    /// For JSON content, deserializes to the specified type.
    /// For raw content like JWT strings, use string as the type parameter.
    /// </summary>
    /// <typeparam name="T">The type to deserialize the response to. Use string for raw text content.</typeparam>
    /// <param name="uri">The URI to fetch content from.</param>
    /// <returns>
    /// A Result containing either the deserialized content or an OidcError if the fetch operation fails.
    /// </returns>
    Task<Result<T, OidcError>> FetchAsync<T>(Uri uri);
}
