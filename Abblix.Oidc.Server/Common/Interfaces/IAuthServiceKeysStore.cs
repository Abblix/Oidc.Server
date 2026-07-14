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

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// The write-role counterpart to <see cref="IAuthServiceKeysProvider"/>: it persists a service key at the
/// moment it is generated, so its public half survives even when the external keystore that holds the
/// private half exposes it only once. Reading stays with <see cref="IAuthServiceKeysProvider"/>.
/// </summary>
/// <remarks>
/// The roles are segregated deliberately (Interface Segregation): this is NOT
/// <c>IAuthServiceKeysStore : IAuthServiceKeysProvider</c>. A component that only reads keys (the JWKS
/// endpoint, the token validators) depends on the reader alone and is never coupled to persistence; the
/// key generator depends on the writer alone. A persistent implementation implements BOTH role interfaces
/// over one durable backend, but the two contracts stay decoupled. The durable backend, key generation,
/// and the rotation that advances a descriptor's status ship separately.
/// </remarks>
public interface IAuthServiceKeysStore
{
    /// <summary>
    /// Persists a newly generated key with its lifecycle window, so it is available to the read seam for
    /// verification and publication before it is ever used to sign (publish-before-sign).
    /// </summary>
    /// <param name="descriptor">The key and the lifecycle metadata that lives around it.</param>
    /// <param name="cancellationToken">Cancels a network-backed persistence round-trip.</param>
    Task AddAsync(AuthServiceKeyDescriptor descriptor, CancellationToken cancellationToken = default);
}
