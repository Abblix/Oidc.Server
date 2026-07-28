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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Resolves a protected resource's encryption keys from its registration, inline or at its JWKS URI.
/// </summary>
/// <param name="logger">Logger for capturing fetch operations and errors.</param>
/// <param name="serviceProvider">Used to resolve the scoped <see cref="ISecureHttpFetcher"/> per fetch.</param>
public class ResourceKeysProvider(
    ILogger<ResourceKeysProvider> logger,
    IServiceProvider serviceProvider) : IResourceKeysProvider
{
    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(ResourceDefinition definition)
        => serviceProvider
            .ResolveKeysAsync(
                definition.Jwks,
                definition.JwksUri,
                logger,
                definition.Resource.OriginalString,
                KeySetOwners.Resource)
            // A key set may serve both roles, and only the encryption half can be used here. A key that
            // declares no use is usable for either, per RFC 7517 Section 4.2, so it is kept.
            .Where(key => key.Usage is null or PublicKeyUsages.Encryption);
}
