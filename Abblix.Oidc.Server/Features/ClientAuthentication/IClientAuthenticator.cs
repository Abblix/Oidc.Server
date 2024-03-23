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

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Defines the interface for client authentication, supporting various authentication methods during OAuth flows.
/// </summary>
public interface IClientAuthenticator
{
    /// <summary>
    /// Specifies the authentication methods supported by this authenticator.
    /// This property should return a value that identify the authentication scheme
    /// (e.g., "client_secret_basic", "private_key_jwt") supported by the implementer.
    /// </summary>
    IEnumerable<string> ClientAuthenticationMethodsSupported { get; }
    
    /// <summary>
    /// Attempts to authenticate a client based on the provided request.
    /// It verifies the client's credentials and determines the authenticity of the client.
    /// </summary>
    /// <param name="request">The client request containing authentication information.</param>
    /// <returns>
    /// A task that resolves to the authenticated <see cref="ClientInfo"/> if successful,
    /// or null if authentication fails.
    /// </returns>
    Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request);
}
