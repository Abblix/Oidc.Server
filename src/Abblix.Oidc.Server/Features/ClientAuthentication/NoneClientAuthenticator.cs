// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates clients that are configured as public, without requiring client secrets.
/// </summary>
/// <remarks>
/// This authenticator is designed for public clients where client secrets cannot be securely stored. It ensures that
/// only clients marked as public in the configuration are allowed to proceed without client authentication.
/// This approach is typically used in scenarios where the client application runs in an environment that
/// cannot securely maintain a secret, such as single-page applications or native mobile apps.
/// </remarks>
/// <param name="logger">The logger for logging authentication events.</param>
/// <param name="clientInfoProvider">The provider for retrieving client information.</param>
public partial class NoneClientAuthenticator(
    ILogger<NoneClientAuthenticator> logger,
    IClientInfoProvider clientInfoProvider): IClientAuthenticator
{
    /// <summary>
    /// Indicates the client authentication method supported by this authenticator.
    /// For this authenticator, no client authentication is required, aligning with scenarios where
    /// client authentication is deemed unnecessary or where anonymous access is permitted.
    /// </summary>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.None; }
    }

    /// <summary>
    /// Attempts to authenticate a client based solely on its ID, without requiring a client secret.
    /// </summary>
    /// <param name="request">The client request containing the client's ID.</param>
    /// <returns>A task that returns the authenticated <see cref="ClientInfo"/>
    /// if successful, or null if authentication fails.</returns>
    /// <remarks>
    /// This method is suitable for public clients where a secret is not issued or cannot be securely stored.
    /// It verifies the existence of the client and ensures it is marked as a public client in the configuration.
    /// Clients not meeting these criteria are not authenticated.
    /// </remarks>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        var clientId = request.ClientId;
        if (!clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        switch (client)
        {
            case null:
                LogClientNotFound(clientId);
                return null;

            case { TokenEndpointAuthMethod: ClientAuthenticationMethods.None }:
                return client;

            default:
                return null;
        }
    }
}
