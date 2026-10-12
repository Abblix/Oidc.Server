// Abblix OIDC Client Library
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
/// Serves the provider metadata the host wrote in configuration, for a provider that publishes no discovery
/// document.
/// </summary>
/// <remarks>
/// Plenty of OAuth 2.0 providers never adopted OpenID Connect Discovery, so their endpoints are known only
/// from their documentation. Rather than making those providers a special case throughout the client, the
/// host declares the same metadata by hand and every consumer keeps reading it through
/// <see cref="IProviderMetadataProvider"/>, unaware of where it came from.
///
/// Nothing is fetched and nothing is cached here: the configured document is already in memory, and it
/// changes only when the host is reconfigured and restarted.
/// </remarks>
public sealed class ConfiguredMetadataProvider : IProviderMetadataProvider
{
    private readonly ProviderMetadata _metadata;

    /// <summary>
    /// Creates the provider over the metadata the host registered.
    /// </summary>
    public ConfiguredMetadataProvider(ProviderMetadata metadata) => _metadata = metadata;

    /// <inheritdoc />
    public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_metadata);
}
