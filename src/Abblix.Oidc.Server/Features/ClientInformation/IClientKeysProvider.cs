// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Provides access to cryptographic keys for OpenID Connect clients, supporting token encryption and signature validation.
/// </summary>
/// <remarks>
/// This interface serves as a bridge between OAuth 2.0/OpenID Connect clients and the cryptographic keys necessary
/// for securing JWT tokens. It enables dynamic retrieval of encryption and signing keys which can be used for
/// token encryption, signature, and validation processes. This approach supports scenarios where keys are rotated
/// or updated without requiring service restarts or manual intervention.
/// </remarks>
public interface IClientKeysProvider
{
    /// <summary>
    /// Retrieves the set of encryption keys associated with a given client, allowing the service to encrypt
    /// JWT tokens or other sensitive information intended for that client.
    /// </summary>
    /// <param name="clientInfo">The client's information, used to identify the correct set of encryption keys.</param>
    /// <returns>An asynchronous stream (<see cref="IAsyncEnumerable{T}"/>) of <see cref="JsonWebKey"/>, providing access to each key.</returns>
    /// <remarks>
    /// This method is essential for services that issue encrypted tokens or need to securely communicate with clients,
    /// ensuring that only the intended recipient can decrypt and access the transmitted information.
    /// </remarks>
    IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(ClientInfo clientInfo);

    /// <summary>
    /// Retrieves the set of signing keys associated with a given client, enabling the service to validate
    /// signatures on JWT tokens or other signed payloads originating from that client.
    /// </summary>
    /// <param name="clientInfo">The client's information, used to identify the correct set of signing keys.</param>
    /// <returns>An asynchronous stream (<see cref="IAsyncEnumerable{T}"/>) of <see cref="JsonWebKey"/>, providing access to each key.</returns>
    /// <remarks>
    /// This method supports secure client-server interactions by enabling the service to verify the authenticity
    /// of incoming signed data, ensuring it was not tampered with and was indeed issued by the claiming client.
    /// </remarks>
    IAsyncEnumerable<JsonWebKey> GetSigningKeys(ClientInfo clientInfo);
}
