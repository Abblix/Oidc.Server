// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.Signing;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates clients using the Private Key JWT method, verifying the client's identity through a signed JWT
/// that the client provides. This method is suitable for clients that can securely store and use private keys.
/// </summary>
/// <param name="logger">Logger for recording the authentication process and any issues encountered.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="serviceProvider">Service provider used to resolve scoped dependencies.</param>
/// <param name="timeProvider">Judges the assertion's timestamps against the client's own profile.</param>
/// <param name="options">Where the longest lifetime an assertion may have is read from.</param>
public class PrivateKeyJwtAuthenticator(
    ILogger<PrivateKeyJwtAuthenticator> logger,
    IReplayCache replayCache,
    IServiceProvider serviceProvider,
    TimeProvider timeProvider,
    IOptionsMonitor<OidcOptions> options)
    : JwtAssertionAuthenticatorBase(logger, replayCache, timeProvider, serviceProvider, options)
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

    /// <inheritdoc />
    /// <remarks>
    /// An assertion signed with an algorithm of <see cref="AssertionAlgorithms"/>, and a JWE. And one signed with no
    /// method's algorithm - "none", an algorithm this server does not support, a header that does not read - which
    /// client_secret_jwt passes over, so it is refused here, with the one warning, rather than by neither method.
    /// </remarks>
    protected override bool Reads(string assertion)
    {
        if (ClientAssertionSigning.IsEncrypted(assertion))
            return true;

        // A header that does not read names no method's algorithm
        if (ClientAssertionSigning.AlgorithmOf(assertion) is not { } algorithm)
            return true;

        using var scope = Services.CreateScope();
        var own = AssertionAlgorithms(scope.ServiceProvider);

        var claimedByNoMethod = !own.Contains(algorithm) && !ClientSigningKeys.SecretAlgorithms.Contains(algorithm);
        return own.Contains(algorithm) || claimedByNoMethod;
    }

    /// <summary>
    /// The algorithms a private_key_jwt assertion may be signed with: those the JWT validator supports that sign with a
    /// private key rather than a shared secret.
    /// </summary>
    private static IReadOnlySet<string> AssertionAlgorithms(IServiceProvider services)
        => AsymmetricAlgorithms.Among(services.GetRequiredService<IJsonWebTokenValidator>().SigningAlgorithmsSupported);

    /// <summary>
    /// Validates the JWT assertion using the client's public keys from JWKS.
    /// </summary>
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
        var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();

        // Stated rather than left to the default, because the requirements are this method's and not the
        // validator's, which also reads request objects: the base class judges the type and the audience after
        // validation, by RFC 10070 section 4. A private key signs asymmetrically, so an assertion signed with a
        // shared secret is refused before its issuer is looked up
        return await tokenValidator.ValidateAsync(
            tenant,
            client: null,
            clients,
            jwt,
            TokenTypePolicy.CheckedByCaller,
            AssertionAlgorithms(scope.ServiceProvider),
            AssertionValidationOptions);
    }
}
