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

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Turns the document a provider published into the document this client acts upon, applying
/// RFC 8414 section 2.1 <c>signed_metadata</c> where the host has arranged for it to mean something.
/// </summary>
/// <remarks>
/// The specification makes every part of this conditional on the consumer: "If the consumer of the metadata
/// supports signed metadata, metadata values conveyed in the signed metadata MUST take precedence over the
/// corresponding values conveyed using plain JSON elements". Whether this client supports it is therefore a
/// deployment decision, and it is expressed by which implementation of this interface is registered.
/// </remarks>
public interface ISignedMetadataVerifier
{
    /// <summary>
    /// Returns the effective metadata for <paramref name="document"/>.
    /// </summary>
    /// <param name="document">The document exactly as the provider published it.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The document this client acts upon, which may be the one passed in.</returns>
    /// <exception cref="ProviderMetadataException">
    /// The document did not meet what the host asked of it, so there is no metadata to act upon.
    /// </exception>
    Task<JsonObject> ApplyAsync(JsonObject document, CancellationToken cancellationToken = default);
}
