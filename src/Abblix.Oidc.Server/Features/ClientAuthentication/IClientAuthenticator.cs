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
    /// Names where in the request each credential of the form this authenticator reads is presented, by the same rule
    /// <see cref="TryAuthenticateClientAsync"/> answers <see cref="ClientAuthenticationFailures.NoCredential"/> by,
    /// and without checking any of them: no secret is compared, no signature verified, nothing spent. A request in
    /// which the authenticators together name more than one place uses more than one client authentication method,
    /// which RFC 6749 section 2.3 forbids, and is refused before any credential is checked.
    /// </summary>
    /// <remarks>
    /// A place is named by the <see cref="ClientRequest"/> member the credential is read from (for example
    /// <c>nameof(ClientRequest.ClientSecret)</c>), so two authenticators reading the same credential name the same place
    /// and it counts once: a client assertion is read by both the client_secret_jwt and the private_key_jwt
    /// authenticators, a TLS client certificate by both mutual-TLS ones. A host's authenticator reading a credential
    /// the request model does not carry names a place of its own. None named means the request presents no credential
    /// this authenticator reads.
    /// </remarks>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The client request.</param>
    /// <returns>The places, each named once.</returns>
    Task<IEnumerable<string>> FindPresentedCredentialsAsync(TenantDefinition tenant, ClientRequest request);

    /// <summary>
    /// Attempts to authenticate a client based on the provided request, answering one of three outcomes: the client
    /// the request proves; a credential of the form this authenticator reads presented and not valid
    /// (<see cref="ClientAuthenticationFailures.InvalidCredential"/> or another <c>invalid_client</c>); or no
    /// credential of that form presented at all (<see cref="UnauthenticatedCallerError"/>, as
    /// <see cref="ClientAuthenticationFailures.NoCredential"/>). An authenticator decides what counts as presented from
    /// what it itself reads, a client_id alone being an identifier rather than a credential. An authenticator composing
    /// others answers a fourth: <see cref="ClientAuthenticationFailures.MoreThanOneMethod"/>, for a request in which
    /// they find credentials in more than one place (<see cref="FindPresentedCredentialsAsync"/>).
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
