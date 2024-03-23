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
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Implements the functionality to send logout tokens to clients via back-channel communication,
/// adhering to the OpenID Connect back-channel logout specification.
/// </summary>
public class BackChannelLogoutTokenSender : ILogoutTokenSender
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BackChannelLogoutTokenSender"/> class with the specified logger,
    /// JWT formatter, and HTTP client.
    /// </summary>
    /// <param name="logger">The logger to use for logging information about the logout token sending process.</param>
    /// <param name="jwtFormatter">The formatter responsible for creating JWTs to be sent as logout tokens.</param>
    /// <param name="backChannelHttpClient">The HTTP client used for sending the logout tokens to clients over the
    /// back channel.</param>
    public BackChannelLogoutTokenSender(
        ILogger<BackChannelLogoutTokenSender> logger,
        IClientJwtFormatter jwtFormatter,
        HttpClient backChannelHttpClient)
    {
        _logger = logger;
        _jwtFormatter = jwtFormatter;
        _backChannelHttpClient = backChannelHttpClient;
    }

    private readonly ILogger _logger;
    private readonly IClientJwtFormatter _jwtFormatter;
    private readonly HttpClient _backChannelHttpClient;

    /// <summary>
    /// Asynchronously sends a logout token directly to a client over the back channel.
    /// </summary>
    /// <param name="clientInfo">Information about the client to which the logout token is sent.</param>
    /// <param name="logoutToken">The logout token to be sent.</param>
    /// <returns>A task representing the asynchronous operation of sending the logout token.</returns>
    /// <remarks>
    /// This method constructs a back-channel HTTP POST request containing the logout token
    /// and sends it to the client's back-channel logout URI.
    /// It ensures that the HTTP response indicates successful delivery of the logout token.
    /// </remarks>
    public async Task SendBackChannelLogoutAsync(ClientInfo clientInfo, EncodedJsonWebToken logoutToken)
    {
        var logoutOptions = clientInfo.BackChannelLogout.NotNull(nameof(clientInfo.BackChannelLogout));

        var parameters = new KeyValuePair<string, string>[]
        {
            new ("logout_token", logoutToken.EncodedJwt),
        };

        using var content = new FormUrlEncodedContent(parameters);
        using var response = await _backChannelHttpClient.PostAsync(logoutOptions.Uri, content);

        _logger.LogDebug("The request with {@Parameters} was sent to {Uri}, the status code {StatusCode} was received",
            parameters, logoutOptions.Uri, response.StatusCode);

        response.EnsureSuccessStatusCode();
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Failed to send logout token to {Uri}. Status code: {StatusCode}",
                logoutOptions.Uri, response.StatusCode);
        }
    }
}
