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
public class NoneClientAuthenticator: IClientAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NoneClientAuthenticator"/> class.
    /// </summary>
    /// <param name="logger">The logger for logging authentication events.</param>
    /// <param name="clientInfoProvider">The provider for retrieving client information.</param>
    /// <remarks>
    /// This constructor prepares the authenticator with necessary dependencies for client lookup and logging.
    /// </remarks>
    public NoneClientAuthenticator(
        ILogger<NoneClientAuthenticator> logger,
        IClientInfoProvider clientInfoProvider)
    {
        _logger = logger;
        _clientInfoProvider = clientInfoProvider;
    }

    private readonly ILogger _logger;
    private readonly IClientInfoProvider _clientInfoProvider;

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
    /// <returns>A task that represents the asynchronous operation, returning the authenticated <see cref="ClientInfo"/> if successful, or null if authentication fails.</returns>
    /// <remarks>
    /// This method is suitable for public clients where a secret is not issued or cannot be securely stored. It verifies the existence of the client
    /// and ensures it is marked as a public client in the configuration. Clients not meeting these criteria are not authenticated.
    /// </remarks>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        var clientId = request.ClientId;
        if (!clientId.HasValue())
            return null;

        var client = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (client == null)
        {
            _logger.LogDebug("Client authentication failed: Client information with id {ClientId} is missing", clientId);
            return null;
        }

        if (client.ClientType == ClientType.Public)
            return client;

        return null;

    }
}
