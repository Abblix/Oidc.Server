// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates clients using the Private Key JWT method, verifying the client's identity through a signed JWT
/// that the client provides. This method is suitable for clients that can securely store and use private keys.
/// </summary>
/// <param name="logger">Logger for recording the authentication process and any issues encountered.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="serviceProvider">Service provider used to resolve scoped dependencies.</param>
/// <param name="issuerProvider">Supplies the issuer identifier a profile-governed assertion must name.</param>
/// <param name="options">Supplies the server-wide default security profile.</param>
/// <param name="timeProvider">Judges the assertion's timestamps against the client's own profile.</param>
public class PrivateKeyJwtAuthenticator(
    ILogger<PrivateKeyJwtAuthenticator> logger,
    IReplayCache replayCache,
    IServiceProvider serviceProvider,
    IIssuerProvider issuerProvider,
    IOptions<OidcOptions> options,
    TimeProvider timeProvider)
    : JwtAssertionAuthenticatorBase(logger, replayCache, issuerProvider, options, timeProvider)
{
    /// <summary>
    /// Indicates the client authentication method supported by this authenticator.
    /// This method uses private keys and JSON Web Tokens (JWT) for client authentication,
    /// allowing clients to assert their identity through the use of asymmetric key cryptography.
    /// It is designed for environments where the client can securely hold a private key.
    /// </summary>
    public override IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.PrivateKeyJwt; }
    }

    /// <summary>
    /// Validates the JWT assertion using the client's public keys from JWKS.
    /// </summary>
    /// <param name="jwt">The JWT assertion to validate.</param>
    /// <returns>
    /// A Result containing either a ValidJsonWebToken on success, or a JwtValidationError on failure.
    /// </returns>
    protected override async Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateJwtAsync(string jwt)
    {
        using var scope = serviceProvider.CreateScope();
        var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();

        // Stated rather than left to the default, because the requirement is this grant's and not
        // the validator's: RFC 7521 Section 5.2 requires the assertion to carry an "Expires At
        // entity that limits the time window during which the assertion can be used", which
        // RFC 7523 Section 3 item 4 spells as a MUST on exp.
        return await tokenValidator.ValidateAsync(
            jwt, ValidationOptions.Default | ValidationOptions.RequireExpirationTime);
    }
}
