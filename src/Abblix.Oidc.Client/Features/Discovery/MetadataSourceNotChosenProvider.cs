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

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Stands in for a metadata source the host never chose, and fails loudly when anything asks it for metadata.
/// </summary>
/// <remarks>
/// Where the provider's endpoints come from is a decision the host has to make: reading them from a discovery
/// document and reading them from configuration are different trust models, so neither is a safe default to
/// pick silently. Registering this guard makes the omission a clear error naming the two calls, instead of a
/// missing-service message or, worse, a quiet fallback.
/// </remarks>
public sealed class MetadataSourceNotChosenProvider : IProviderMetadataProvider
{
    /// <inheritdoc />
    public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
        => throw new ProviderMetadataException(
            "No source of OpenID Provider metadata is registered. Call AddDiscovery() to read the provider's "
            + "discovery document, or AddConfiguredMetadata() to supply the provider's endpoints directly for "
            + "a provider that publishes no document.");
}
