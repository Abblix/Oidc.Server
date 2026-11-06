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
/// Supplies the OpenID Provider's discovery metadata to the rest of the client.
/// </summary>
/// <remarks>
/// Every consumer reads the provider's endpoints through this contract rather than from configuration, so a
/// provider that moves an endpoint is followed automatically. Implementations are expected to cache: this is
/// called on every authorization request, and the document changes rarely.
/// </remarks>
public interface IProviderMetadataProvider
{
    /// <summary>
    /// Returns the provider's metadata, fetching it if no valid cached copy is held.
    /// </summary>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>The provider's discovery metadata.</returns>
    /// <exception cref="ProviderMetadataException">
    /// The document could not be fetched, could not be parsed, or failed the issuer check.
    /// </exception>
    Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default);
}
