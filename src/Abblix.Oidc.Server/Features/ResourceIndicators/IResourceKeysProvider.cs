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

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Supplies the encryption keys a protected resource publishes, so an access token minted for it can be
/// encrypted to the party that reads it rather than to this server.
/// </summary>
/// <remarks>
/// The service-side counterpart of <see cref="ClientInformation.IClientKeysProvider"/>: same two forms
/// (inline in the registration, or fetched from a JWKS URI), same SSRF-protected and cached path. Only the
/// owner differs, and with it who can decrypt the result.
/// </remarks>
public interface IResourceKeysProvider
{
    /// <summary>
    /// Retrieves the encryption keys published by the given resource.
    /// </summary>
    /// <param name="definition">The registered definition of the resource.</param>
    /// <returns>The resource's encryption keys, empty when it publishes none, which is how a resource says it
    /// accepts a signed JWS.</returns>
    IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(ResourceDefinition definition);
}
