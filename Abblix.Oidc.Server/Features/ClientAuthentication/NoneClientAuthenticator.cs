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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Utils.Sanitized;

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
public class NoneClientAuthenticator(
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
                logger.LogDebug("Client authentication failed: Client information with id {ClientId} is missing", Value(clientId));
                return null;

            case { TokenEndpointAuthMethod: ClientAuthenticationMethods.None }:
                return client;

            default:
                return null;
        }
    }
}
