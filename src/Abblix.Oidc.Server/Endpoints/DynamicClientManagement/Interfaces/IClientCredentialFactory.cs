// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Encapsulates client credential generation to maintain single responsibility and reduce constructor complexity.
/// Separates credential-specific concerns (ID generation, secret generation, hashing, expiration) from
/// the broader client registration process.
/// </summary>
public interface IClientCredentialFactory
{
    /// <summary>
    /// Creates credentials with authentication-method-aware secret generation.
    /// Generates secrets only for methods requiring them (client_secret_basic, client_secret_post, client_secret_jwt),
    /// avoiding unnecessary secret generation for public clients or private_key_jwt authentication.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">Determines secret generation strategy based on OAuth 2.0 authentication method.</param>
    /// <param name="clientId">Allows pre-registration scenarios where the client ID is externally provided.</param>
    /// <returns>Complete credential set including both transmission format (plain secret) and storage format (hash).</returns>
    ClientCredentials Create(string tokenEndpointAuthMethod, string? clientId = null);
}
