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
