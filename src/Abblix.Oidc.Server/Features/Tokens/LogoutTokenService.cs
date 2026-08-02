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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.SecurityEvents;
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

        // The logout token is a Security Event Token, so the SET envelope comes from the shared
        // builder and its rules hold by construction: the required claims cannot be omitted, the
        // logout order is one event statement carrying the empty object, and 'nonce' - which
        // Back-Channel Logout PROHIBITS
        // (https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken) - has no door
        // to come in through.
        var builder = new SecurityEventTokenBuilder()
            .WithIssuer(logoutContext.Issuer)
            .WithAudience(clientInfo.ClientId)
            .WithJwtId(tokenIdGenerator.GenerateTokenId())
            .WithIssuedAt(issuedAt)
            .WithEvent(LogoutTokenEvents.BackChannelLogout);

        // Either identifier may be absent - the guard above requires one of the two - and an
        // absent one stays off the wire entirely rather than travelling as an empty value.
        if (!string.IsNullOrEmpty(subjectId))
        {
            builder.WithSubject(subjectId);
        }

        if (!string.IsNullOrEmpty(logoutContext.SessionId))
        {
            builder.WithClaim(IanaClaimTypes.Sid, logoutContext.SessionId);
        }

        var logoutToken = builder.Build().Token;

        // Where Back-Channel Logout deliberately departs from the SET default profile, each
        // departure is one visible line on the open token model, which the builder refuses to
        // write by design: §2.4 registers the token's own type, and REQUIRES an expiration -
        // for a logout order, expiry is what bounds how long a lost token still logs somebody
        // out - where a generic SET must carry none.
        logoutToken.Header.Type = JsonWebTokenTypes.LogoutToken;
        logoutToken.Payload.NotBefore = issuedAt;
        logoutToken.Payload.ExpiresAt = issuedAt + logoutOptions.LogoutTokenExpiresIn;

        // Back-Channel Logout 1.0 Section 2.4 signs the logout token with the same keys as the
        // ID Token, so the algorithm follows the client's ID Token registration unless the host
        // set the explicit per-client override; ResolveSigningAlgorithm owns the one value that
        // cannot be inherited.
        logoutToken.Header.Algorithm = ResolveSigningAlgorithm(clientInfo);

        LogTokenPrepared(logoutToken);

        var jwt = await jwtFormatter.FormatAsync(
            logoutToken,
            clientInfo,
            ClientJwtEncryption.ForIdentityToken(clientInfo, options.Value));

        return new EncodedJsonWebToken(logoutToken, jwt);
    }

    /// <summary>
    /// Picks the logout token's signature algorithm: the host's explicit per-client override
    /// wins, otherwise the client's registered ID Token algorithm - Back-Channel Logout 1.0
    /// Section 2.4 signs a logout token with the same keys as ID Tokens, so the ID Token
    /// registration is the natural source of the algorithm too.
    /// </summary>
    /// <remarks>
    /// The "none" branch is the one value inheritance must not carry across. A client whose
    /// response types return no ID Token from the authorization endpoint may legally register
    /// <c>id_token_signed_response_alg=none</c> (Dynamic Client Registration 1.0 Section 2) -
    /// there is simply nothing to sign. A logout token has no such escape: it "MUST be signed"
    /// (Back-Channel Logout 1.0 Section 2.4), and validation is told both what to refuse and
    /// what to expect - "an alg with the value none MUST NOT be used for Logout Tokens", while
    /// the value "SHOULD be the default of RS256" (Section 2.6). So an inherited "none" becomes
    /// RS256, the exact value Section 2.6 names, instead of being honored into a logout order
    /// no receiver could verify.
    /// </remarks>
    private static string ResolveSigningAlgorithm(ClientInfo clientInfo)
        => (clientInfo.LogoutTokenSignedResponseAlgorithm ??
            clientInfo.IdentityTokenSignedResponseAlgorithm) switch
        {
            SigningAlgorithms.None => SigningAlgorithms.RS256,
            var algorithm => algorithm,
        };
}
