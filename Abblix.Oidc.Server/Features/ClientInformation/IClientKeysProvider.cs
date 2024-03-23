// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
