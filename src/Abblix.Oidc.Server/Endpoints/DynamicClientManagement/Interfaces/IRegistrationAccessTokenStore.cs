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
/// Records, for each registered client, the identifier (jti) of the registration access token
/// currently authorized to manage it via the RFC 7592 client configuration endpoint. The token
/// validator accepts only a token whose jti matches the stored value, so rotating the token on
/// update (storing a fresh jti) invalidates every previously issued token (RFC 7592 §5).
/// </summary>
/// <remarks>
/// The binding outlives any single request and must be shared across all server replicas, so the
/// default implementation persists it in the distributed entity storage rather than in process
/// memory. The binding has no expiration — it lives as long as the client is registered — and is
/// removed when the client is deregistered.
/// </remarks>
public interface IRegistrationAccessTokenStore
{
    /// <summary>
    /// Records <paramref name="tokenId"/> as the jti of the client's current registration access
    /// token, replacing any previously stored value (which thereby becomes invalid).
    /// </summary>
    /// <param name="clientId">The identifier of the client the token manages.</param>
    /// <param name="tokenId">The jti embedded in the newly issued registration access token.</param>
    Task SetTokenIdAsync(string clientId, string tokenId);

    /// <summary>
    /// Retrieves the jti of the client's current registration access token.
    /// </summary>
    /// <param name="clientId">The identifier of the client.</param>
    /// <returns>
    /// The stored jti, or <c>null</c> when no binding is recorded (a statically configured client,
    /// or one registered before the binding existed) — in which case the validator does not enforce
    /// the binding.
    /// </returns>
    Task<string?> GetTokenIdAsync(string clientId);

    /// <summary>
    /// Removes the binding for a deregistered client.
    /// </summary>
    /// <param name="clientId">The identifier of the client being removed.</param>
    Task RemoveAsync(string clientId);
}
