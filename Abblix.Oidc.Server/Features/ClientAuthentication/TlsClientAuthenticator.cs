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
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get
        {
            // Only advertise self-signed variant which we fully support here.
            yield return ClientAuthenticationMethods.SelfSignedTlsClientAuth;
        }
    }

    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        // Require client certificate and client_id
        var certificate = request.ClientCertificate;
        if (certificate == null)
            return null;

        var clientId = request.ClientId;
        if (!clientId.NotNullOrWhiteSpace())
            return null;

        var client = await clientInfoProvider.TryFindClientAsync(clientId!).WithLicenseCheck();
        if (client == null)
        {
            logger.LogDebug("mTLS auth failed: unknown client_id {ClientId}", clientId);
            return null;
        }

        if (!string.Equals(client.TokenEndpointAuthMethod, ClientAuthenticationMethods.SelfSignedTlsClientAuth, StringComparison.Ordinal))
        {
            // We currently only support self-signed mTLS in this authenticator
            return null;
        }

        // Compute certificate public key and compare against client's JWKS signing keys
        var certJwk = certificate.ToJsonWebKey();
        if (certJwk is not RsaJsonWebKey certRsa)
        {
            logger.LogDebug("mTLS auth failed: unsupported certificate key type for client {ClientId}", clientId);
            return null;
        }

        await foreach (var key in clientKeysProvider.GetSigningKeys(client))
        {
            if (key is RsaJsonWebKey rsa &&
                rsa.Modulus != null && rsa.Exponent != null &&
                certRsa.Modulus != null && certRsa.Exponent != null &&
                rsa.Modulus.AsSpan().SequenceEqual(certRsa.Modulus) &&
                rsa.Exponent.AsSpan().SequenceEqual(certRsa.Exponent))
            {
                logger.LogInformation("mTLS client authenticated via self-signed certificate for client_id {ClientId}", clientId);
                return client;
            }
        }

        logger.LogWarning("mTLS auth failed: no matching JWKS public key found for client_id {ClientId}", clientId);
        return null;
    }
}

