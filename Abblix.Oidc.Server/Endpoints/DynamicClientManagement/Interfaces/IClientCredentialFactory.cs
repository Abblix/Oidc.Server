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
