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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Implements the <see cref="ILogoutTokenService"/> interface to generate logout tokens.
/// </summary>
/// <param name="logger">Logger for logging operations related to logout token generation.</param>
/// <param name="clock">Clock used for setting token validity timestamps.</param>
/// <param name="subjectTypeConverter">
/// Converter for transforming subject identifiers based on client configurations.</param>
/// <param name="jwtFormatter">Formatter for encoding the generated logout token into a compact serialized format.
/// </param>
/// <param name="tokenIdGenerator">Generator for creating unique JWT identifiers.</param>
/// <param name="options">Supplies the default content-encryption algorithm used when the client registered a
/// key-management algorithm but no <c>id_token_encrypted_response_enc</c>.</param>
public partial class LogoutTokenService(
    ILogger<LogoutTokenService> logger,
    TimeProvider clock,
    ISubjectTypeConverter subjectTypeConverter,
    IClientJwtFormatter jwtFormatter,
    ITokenIdGenerator tokenIdGenerator,
    IOptions<OidcOptions> options) : ILogoutTokenService
{
    /// <summary>
    /// Asynchronously creates a logout token based on the provided client information and logout event context.
    /// The token is then encoded to a serialized string format for easy distribution to clients.
    /// </summary>
    /// <param name="clientInfo">Information about the client that will receive the logout token.</param>
    /// <param name="logoutContext">Contextual information about the logout event, including the user's subject ID
    /// and session ID.</param>
    /// <returns>A task that returns a logout token.
    /// The task result is an <see cref="EncodedJsonWebToken"/>, which includes both the raw token object and its
    /// string representation.</returns>
    public async Task<EncodedJsonWebToken> CreateLogoutTokenAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        var logoutOptions = clientInfo.BackChannelLogout.NotNull(nameof(clientInfo.BackChannelLogout));
        if (logoutOptions.RequiresSessionId && string.IsNullOrEmpty(logoutContext.SessionId))
        {
            throw new InvalidOperationException($"The client {clientInfo.ClientId} requires session id");
        }

        var subjectId = subjectTypeConverter.Convert(logoutContext.SubjectId, clientInfo);
        if (string.IsNullOrEmpty(subjectId) && string.IsNullOrEmpty(logoutContext.SessionId))
        {
            throw new InvalidOperationException(
                $"Both {nameof(subjectId)} and {nameof(logoutContext.SessionId)} are null or empty, unable to specify the session should be finished");
        }

        var issuedAt = clock.GetUtcNow();

        var logoutToken = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.LogoutToken,
                // Back-Channel Logout §2.4: the logout token is signed in the same manner as the
                // ID Token, so the client's ID Token signing algorithm is the default; a host may
                // diverge per client via the explicit LogoutTokenSignedResponseAlgorithm override.
                // The previous hardcoded RS256 produced tokens an ES256/PS256-registered client
                // would reject on signature-algorithm verification. The same §2.4 also demands
                // "A Logout Token MUST be signed" and that none "MUST NOT be used": a client whose
                // response types return no ID Token from the authorization endpoint may legally
                // register id_token_signed_response_alg=none, so that value cannot be inherited
                // here — fall back to RS256, which every OIDC client is required to support.
                Algorithm = ResolveSigningAlgorithm(clientInfo),
            },
            Payload =
            {
                // Attention: according to the https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
                // the nonce is PROHIBITED in Logout tokens.

                JwtId = tokenIdGenerator.GenerateTokenId(),

                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + logoutOptions.LogoutTokenExpiresIn,

                Issuer = logoutContext.Issuer,
                Audiences = [clientInfo.ClientId],

                Subject = subjectId,
                SessionId = logoutContext.SessionId,

                [JwtClaimTypes.Events] = new JsonObject
                {
                    { "http://schemas.openid.net/event/backchannel-logout", new JsonObject() },
                }
            },
        };

        LogTokenPrepared(logoutToken);

        var jwt = await jwtFormatter.FormatAsync(
            logoutToken,
            clientInfo,
            ClientJwtEncryption.ForIdentityToken(clientInfo, options.Value));

        return new EncodedJsonWebToken(logoutToken, jwt);
    }

    private static string ResolveSigningAlgorithm(ClientInfo clientInfo)
        => (clientInfo.LogoutTokenSignedResponseAlgorithm ?? clientInfo.IdentityTokenSignedResponseAlgorithm) switch
        {
            SigningAlgorithms.None => SigningAlgorithms.RS256,
            var algorithm => algorithm,
        };
}
