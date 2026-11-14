// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

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
    /// Attempts to authenticate a client based on the provided request, answering one of three outcomes: the client
    /// the request proves; a credential of the form this authenticator reads presented and not valid
    /// (<see cref="ClientAuthenticationFailures.InvalidCredential"/> or another <c>invalid_client</c>); or no
    /// credential of that form presented at all (<see cref="UnauthenticatedCallerError"/>, as
    /// <see cref="ClientAuthenticationFailures.NoCredential"/>). An authenticator decides what counts as presented from
    /// what it itself reads, a client_id alone being an identifier rather than a credential.
    /// </summary>
    /// <remarks>
    /// The two failures are answered differently where a specification tells them apart: RFC 9701 section 5 has the
    /// introspection endpoint "refuse to serve introspection requests that don't authenticate the caller and return an
    /// HTTP status code 400", while RFC 7662 section 2.3 answers invalid credentials with 401.
    /// </remarks>
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="request">The client request containing authentication information.</param>
    /// <returns>The authenticated client, or why it is not one.</returns>
    Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(TenantDefinition tenant, ClientRequest request);
}
