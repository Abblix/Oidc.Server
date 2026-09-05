// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
