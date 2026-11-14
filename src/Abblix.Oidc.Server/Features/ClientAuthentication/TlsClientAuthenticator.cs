// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Implements RFC 8705 self-signed TLS client authentication (self_signed_tls_client_auth).
/// Validates the presented client certificate by matching its public key against the client's
/// registered JWKS (jwks or jwks_uri). If matched and the client's configured token endpoint
/// auth method is <c>self_signed_tls_client_auth</c>, the client is authenticated.
/// </summary>
public partial class TlsClientAuthenticator(
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
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="request">The client request containing the certificate and client ID to authenticate.</param>
    /// <returns>
    /// A task that returns the authenticated <see cref="ClientInfo"/>, or why it is not one: no certificate presented
    /// as a credential (none at all, no client_id, or a client_id naming no client registered for this method), or one
    /// whose public key matches no key in the client's JWKS.
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
    public async Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(TenantDefinition tenant, ClientRequest request)
    {
        if (await FindClientAuthenticatingByCertificateAsync(tenant, request) is not (var client, var certificate))
            return ClientAuthenticationFailures.NoCredential;

        // Compute certificate public key and compare against client's JWKS signing keys
        var certJwk = certificate.ToJsonWebKey();
        if (!await clientKeysProvider.GetSigningKeys(client).AnyAsync(PublicKeysMatch(certJwk)))
        {
            LogNoMatchingPublicKey(client.ClientId);
            return ClientAuthenticationFailures.InvalidCredential;
        }

        LogAuthenticated(client.ClientId);
        return client;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> FindPresentedCredentialsAsync(TenantDefinition tenant, ClientRequest request)
        => await FindClientAuthenticatingByCertificateAsync(tenant, request) is not null
            ? [nameof(ClientRequest.ClientCertificate)]
            : [];

    /// <summary>
    /// The client the request's TLS certificate is a credential of, with the certificate: the client its client_id
    /// names, registered for self_signed_tls_client_auth. RFC 8705 section 2 has the requirement of mutual TLS for
    /// client authentication "determined by the authorization server, based on policy or configuration for the given
    /// client", and section 4 has mutual-TLS client authentication and certificate-bound tokens "used independently of
    /// each other", so the certificate of a client registered for another method binds its tokens and is not a second
    /// credential beside that method. Section 2 also has the client include client_id in every request using mutual-TLS
    /// client authentication, so without one the certificate authenticates nobody.
    /// </summary>
    private async Task<(ClientInfo Client, X509Certificate2 Certificate)?> FindClientAuthenticatingByCertificateAsync(
        TenantDefinition tenant, ClientRequest request)
    {
        if (request is not { ClientCertificate: { } certificate, ClientId: var clientId } || !clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(tenant, clientId);
        if (client == null)
        {
            LogClientNotFound(clientId);
            return null;
        }

        // Only the self-signed variant is served here; tls_client_auth has its own authenticator
        if (!ClientAuthenticationMethods.SelfSignedTlsClientAuth.Equals(client.TokenEndpointAuthMethod, StringComparison.Ordinal))
            return null;

        return (client, certificate);
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
                       certCurve == jwkCurve &&
                       certX.SequenceEqual(jwkX) &&
                       certY.SequenceEqual(jwkY),

            _ => _ => false,
        };
    }
}
