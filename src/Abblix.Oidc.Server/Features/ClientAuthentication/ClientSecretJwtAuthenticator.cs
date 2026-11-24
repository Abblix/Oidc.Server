// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates client requests using the client_secret_jwt authentication method.
/// This method is used in scenarios where the client signs a JWT with its secret as a means of authentication.
/// </summary>
/// <param name="logger">Logger for recording the authentication process and any issues encountered.</param>
/// <param name="clock">Judges the assertion's timestamps against the client's own profile.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="options">Where the longest lifetime an assertion may have is read from.</param>
/// <param name="serviceProvider">Resolves per request the validator of the client's JWT, and where the token and
/// backchannel authentication endpoints are served, for a client allowed such a URL as its assertion's
/// audience.</param>
public class ClientSecretJwtAuthenticator(
    ILogger<ClientSecretJwtAuthenticator> logger,
    TimeProvider clock,
    IReplayCache replayCache,
    IServiceProvider serviceProvider,
    IOptionsMonitor<OidcOptions> options)
    : JwtAssertionAuthenticatorBase(logger, replayCache, clock, serviceProvider, options)
{
    /// <summary>
    /// Specifies the client authentication method this authenticator supports, which is 'client_secret_jwt'.
    /// This indicates that the authenticator handles client authentication using JSON Web Tokens (JWT) for
    /// the client secret, as defined in the OpenID Connect specification. It involves using JWTs as
    /// client credentials for authentication, where the JWT assertion is signed by the client's secret key.
    /// </summary>
    public override IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.ClientSecretJwt; }
    }

    /// <summary>
    /// Validates the JWT assertion using HMAC signature with the client secret.
    /// </summary>
    /// <remarks>
    /// The client's JWT validator validates it as it does a private_key_jwt assertion, the keys derived from the
    /// client's secret alone differing: the base class judges whether the client is registered for this method, the
    /// type and the audience after validation, by RFC 10070 section 4. An assertion signed otherwise than with an HS
    /// algorithm is refused before its issuer is looked up.
    /// </remarks>
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="clients">The clients of the request being served, where the client is looked up.</param>
    /// <param name="jwt">The JWT assertion to validate.</param>
    /// <returns>
    /// A Result containing either a ValidJsonWebToken on success, or a JwtValidationError on failure.
    /// </returns>
    protected override async Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateJwtAsync(
        TenantDefinition tenant, IClientInfoProvider clients, string jwt)
    {
        using var scope = Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IClientJwtValidator>().ValidateSecretSignedAsync(
            tenant, clients, jwt, TokenTypePolicy.CheckedByCaller, AssertionValidationOptions);
    }
}
