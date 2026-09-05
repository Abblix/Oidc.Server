// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// This property should return a value that identifies the authentication scheme
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
