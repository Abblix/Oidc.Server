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
