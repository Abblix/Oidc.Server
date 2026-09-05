// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
