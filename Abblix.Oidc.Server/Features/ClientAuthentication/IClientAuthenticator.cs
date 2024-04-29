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
