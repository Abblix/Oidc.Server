// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Decides whether the request's TLS client certificate is a client authentication credential of one mutual-TLS
/// method (RFC 8705 section 2), for the authenticator serving that method.
/// </summary>
/// <remarks>
/// It is one when the client the request's client_id names is registered for that method. RFC 8705 section 2 has the
/// requirement of mutual TLS for client authentication "determined by the authorization server, based on policy or
/// configuration for the given client", and section 4 has mutual-TLS client authentication and certificate-bound
/// tokens "used independently of each other", so the certificate of a client registered for another method binds its
/// tokens and is not a second credential beside that method. Section 2 also has the client include client_id in every
/// request using mutual-TLS client authentication, so without one the certificate authenticates nobody.
/// </remarks>
/// <param name="clientInfoProvider">Finds the client the request's client_id names.</param>
/// <param name="authenticationMethod">The mutual-TLS method the certificate has to be a credential of.</param>
internal sealed class MutualTlsCredential(IClientInfoProvider clientInfoProvider, string authenticationMethod)
{
    /// <summary>
    /// The client the request's certificate is a credential of, with the certificate, or null when it is none.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="request">The client request.</param>
    /// <param name="clientNotFound">Told the client_id that names no client, for the owner to record.</param>
    public async Task<(ClientInfo Client, X509Certificate2 Certificate)?> FindAsync(
        TenantDefinition tenant, ClientRequest request, Action<string>? clientNotFound = null)
    {
        if (request is not { ClientCertificate: { } certificate, ClientId: var clientId } || !clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(tenant, clientId);
        if (client == null)
        {
            clientNotFound?.Invoke(clientId);
            return null;
        }

        if (!authenticationMethod.Equals(client.TokenEndpointAuthMethod, StringComparison.Ordinal))
            return null;

        return (client, certificate);
    }

    /// <summary>
    /// Where the request presents the certificate as a credential of the method, as
    /// <see cref="IClientAuthenticator.FindPresentedCredentialsAsync"/> names it.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The client request.</param>
    /// <param name="clientNotFound">Told the client_id that names no client, for the owner to record.</param>
    public async Task<IEnumerable<string>> FindPresentedAsync(
        TenantDefinition tenant, ClientRequest request, Action<string>? clientNotFound = null)
        => await FindAsync(tenant, request, clientNotFound) is not null
            ? [nameof(ClientRequest.ClientCertificate)]
            : [];
}
