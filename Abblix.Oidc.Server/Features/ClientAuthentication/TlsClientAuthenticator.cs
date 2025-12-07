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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Implements RFC 8705 self-signed TLS client authentication (self_signed_tls_client_auth).
/// Validates the presented client certificate by matching its public key against the client's
/// registered JWKS (jwks or jwks_uri). If matched and the client's configured token endpoint
/// auth method is <c>self_signed_tls_client_auth</c>, the client is authenticated.
/// </summary>
public class TlsClientAuthenticator(
    ILogger<TlsClientAuthenticator> logger,
    IClientInfoProvider clientInfoProvider,
    IClientKeysProvider clientKeysProvider) : IClientAuthenticator
{
    /// <summary>
    /// Gets the collection of client authentication methods supported by this authenticator.
    /// </summary>
    /// <value>
    /// A collection containing <see cref="ClientAuthenticationMethods.SelfSignedTlsClientAuth"/>.
    /// </value>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get
        {
            // Only advertise self-signed variant which we fully support here.
            yield return ClientAuthenticationMethods.SelfSignedTlsClientAuth;
        }
    }

    /// <summary>
    /// Attempts to authenticate a client using self-signed TLS client authentication.
    /// Validates the client certificate's public key against the client's registered JWKS.
    /// </summary>
    /// <param name="request">The client request containing the certificate and client ID to authenticate.</param>
    /// <returns>
    /// A task that returns the authenticated <see cref="ClientInfo"/> if successful; otherwise, null.
    /// Returns null if no certificate is provided, client not found, authentication method doesn't match,
    /// or certificate public key doesn't match any key in the client's JWKS.
    /// </returns>
    /// <remarks>
    /// This method implements RFC 8705 self_signed_tls_client_auth by:
    /// 1. Verifying a client certificate is present
    /// 2. Looking up client configuration by client_id
    /// 3. Checking the client uses self_signed_tls_client_auth method
    /// 4. Extracting the public key from the certificate
    /// 5. Comparing it against all keys in the client's JWKS (jwks or jwks_uri)
    /// Supports both RSA and ECDSA certificates.
    /// </remarks>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        // Require client certificate and client_id
        var certificate = request.ClientCertificate;
        if (certificate == null)
            return null;

        var clientId = request.ClientId;
        if (!clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (client == null)
        {
            logger.LogDebug("mTLS auth failed: unknown client_id {ClientId}", clientId);
            return null;
        }

        if (!ClientAuthenticationMethods.SelfSignedTlsClientAuth.Equals(client.TokenEndpointAuthMethod, StringComparison.Ordinal))
        {
            // We currently only support self-signed mTLS in this authenticator
            return null;
        }

        // Compute certificate public key and compare against client's JWKS signing keys
        var certJwk = certificate.ToJsonWebKey();
        if (!await clientKeysProvider.GetSigningKeys(client).AnyAsync(PublicKeysMatch(certJwk)))
        {
            logger.LogWarning("mTLS auth failed: no matching JWKS public key found for client_id {ClientId}", clientId);
            return null;
        }

        logger.LogInformation("mTLS client authenticated via self-signed certificate for client_id {ClientId}",
            clientId);
        return client;
    }

    /// <summary>
    /// Creates a predicate function that checks if a JWKS key matches the certificate's public key.
    /// Supports RSA and ECDSA key types with appropriate comparison logic for each.
    /// </summary>
    /// <param name="certJwk">The JSON Web Key extracted from the client certificate.</param>
    /// <returns>
    /// A function that takes a <see cref="JsonWebKey"/> from the client's JWKS and returns true if it matches
    /// the certificate's public key; otherwise, false.
    /// Returns a function that always returns false if the certificate key type is unsupported.
    /// </returns>
    /// <remarks>
    /// RSA keys are matched by comparing modulus and exponent.
    /// ECDSA keys are matched by comparing curve name and coordinates (X, Y).
    /// Other key types (EdDSA, symmetric, etc.) are not supported and will not match.
    /// </remarks>
    private static Func<JsonWebKey, bool> PublicKeysMatch(JsonWebKey certJwk)
    {
        return certJwk switch
        {
            RsaJsonWebKey
                {
                    Modulus: { } certModulus,
                    Exponent: { } certExponent,
                } =>
                // RSA key matching
                jwk => jwk is RsaJsonWebKey
                       {
                           Modulus: { } jwkModulus,
                           Exponent: { } jwkExponent,
                       } &&
                       certModulus.SequenceEqual(jwkModulus) &&
                       certExponent.SequenceEqual(jwkExponent),

            EllipticCurveJsonWebKey
                {
                    Curve: { } certCurve,
                    X: { } certX,
                    Y: { } certY,
                } =>
                // ECDSA key matching
                jwk => jwk is EllipticCurveJsonWebKey
                       {
                           Curve: { } jwkCurve,
                           X: { } jwkX,
                           Y: { } jwkY,
                       } &&
                       string.Equals(certCurve, jwkCurve, StringComparison.Ordinal) &&
                       certX.SequenceEqual(jwkX) &&
                       certY.SequenceEqual(jwkY),

            _ => _ => false,
        };
    }
}
