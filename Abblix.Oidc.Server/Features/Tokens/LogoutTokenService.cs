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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Implements the <see cref="ILogoutTokenService"/> interface to generate logout tokens.
/// </summary>
public class LogoutTokenService : ILogoutTokenService
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutTokenService"/> class with required dependencies for
    /// token generation and formatting.
    /// </summary>
    /// <param name="logger">Logger for logging operations related to logout token generation.</param>
    /// <param name="clock">Clock used for setting token validity timestamps.</param>
    /// <param name="subjectTypeConverter">
    /// Converter for transforming subject identifiers based on client configurations.</param>
    /// <param name="jwtFormatter">Formatter for encoding the generated logout token into a compact serialized format.
    /// </param>
    public LogoutTokenService(
        ILogger<LogoutTokenService> logger,
        TimeProvider clock,
        ISubjectTypeConverter subjectTypeConverter,
        IClientJwtFormatter jwtFormatter)
    {
        _logger = logger;
        _clock = clock;
        _subjectTypeConverter = subjectTypeConverter;
        _jwtFormatter = jwtFormatter;
    }

    private readonly ILogger _logger;
    private readonly TimeProvider _clock;
    private readonly ISubjectTypeConverter _subjectTypeConverter;
    private readonly IClientJwtFormatter _jwtFormatter;

    /// <summary>
    /// Asynchronously creates a logout token based on the provided client information and logout event context.
    /// The token is then encoded to a serialized string format for easy distribution to clients.
    /// </summary>
    /// <param name="clientInfo">Information about the client that will receive the logout token.</param>
    /// <param name="logoutContext">Contextual information about the logout event, including the user's subject ID
    /// and session ID.</param>
    /// <returns>A task that represents the asynchronous operation of creating and encoding a logout token.
    /// The task result is an <see cref="EncodedJsonWebToken"/>, which includes both the raw token object and its
    /// string representation.</returns>
    public async Task<EncodedJsonWebToken> CreateLogoutTokenAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        var logoutOptions = clientInfo.BackChannelLogout.NotNull(nameof(clientInfo.BackChannelLogout));
        if (logoutOptions.RequiresSessionId && string.IsNullOrEmpty(logoutContext.SessionId))
        {
            throw new InvalidOperationException($"The client {clientInfo.ClientId} requires session id");
        }

        var subjectId = _subjectTypeConverter.Convert(logoutContext.SubjectId, clientInfo);
        if (string.IsNullOrEmpty(subjectId) && string.IsNullOrEmpty(logoutContext.SessionId))
        {
            throw new InvalidOperationException(
                $"Both {nameof(subjectId)} and {nameof(logoutContext.SessionId)} are null or empty, unable to specify the session should be finished");
        }

        //TODO extract id generator to separate class
        var jwtId = CryptoRandom.GetRandomBytes(16).ToHexString();

        var issuedAt = _clock.GetUtcNow();

        var logoutToken = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.LogoutToken,
                Algorithm = SigningAlgorithms.RS256,
            },
            Payload =
            {
                // Attention: according to the https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
                // the nonce is PROHIBITED in Logout tokens.

                JwtId = jwtId,

                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + logoutOptions.LogoutTokenExpiresIn,

                Issuer = logoutContext.Issuer,
                Audiences = new[] { clientInfo.ClientId },

                Subject = subjectId,
                SessionId = logoutContext.SessionId,

                [JwtClaimTypes.Events] = new JsonObject
                {
                    { "http://schemas.openid.net/event/backchannel-logout", new JsonObject() },
                }
            },
        };

        _logger.LogDebug("The logout token was prepared {@LogoutToken}", logoutToken);

        return new EncodedJsonWebToken(logoutToken, await _jwtFormatter.FormatAsync(logoutToken, clientInfo));
    }
}
