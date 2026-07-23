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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Common.Constants;
using System.Security.Cryptography;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Default <see cref="ITokenAuthorizationContextEvaluator"/>: narrows the originally granted scope and
/// resource sets to the intersection with what the token request asks for (RFC 6749 §6 / RFC 8707 §2.2),
/// and, when the client authenticated via mTLS, derives the RFC 8705 §3 <c>cnf.x5t#S256</c> certificate
/// thumbprint to bind the issued tokens.
/// </summary>
public class TokenAuthorizationContextEvaluator : ITokenAuthorizationContextEvaluator
{
    /// <inheritdoc />
    public AuthorizationContext EvaluateAuthorizationContext(ValidTokenRequest request)
    {
        var authContext = request.AuthorizedGrant.Context;

        // Determine the effective scopes for the token request.
        var scope = authContext.Scope;
        if (scope is { Length: > 0 } && request.Scope is { Length: > 0 })
        {
            scope = scope
                .Intersect(from sd in request.Scope select sd.Scope, StringComparer.Ordinal)
                .ToArray();
        }

        // Determine the effective resources for the token request.
        var resources = authContext.Resources;
        if (resources is { Length: > 0 } && request.Resources is { Length: > 0 })
        {
            resources = resources
                .Intersect(from rd in request.Resources select rd.Resource)
                .ToArray();
        }

        // Return a new authorization context updated with the determined scopes and resources.
        // Certificate-bound confirmation thumbprint (RFC 8705 §3): preserve the binding the
        // grant already carries. RFC 8705 §4 says the AS SHOULD keep a refreshed token bound to
        // the original certificate and check that binding, so an existing thumbprint is never
        // overwritten — neither dropped when no certificate is re-presented on refresh, nor
        // rebound to a rotated certificate. A fresh thumbprint is computed only at initial
        // issuance (no prior binding) when the client authenticated via mTLS.
        var thumbprint = authContext.CertificateSha256Thumbprint;
        if (thumbprint == null && request.ClientCertificate != null)
        {
            // RFC 8705 §3.4: tls_client_certificate_bound_access_tokens decouples certificate
            // binding from the authentication method — a client may authenticate with, say,
            // private_key_jwt over a mutual-TLS connection and still receive certificate-bound
            // tokens. The mTLS authentication methods keep their implicit binding.
            var authMethod = request.ClientInfo.TokenEndpointAuthMethod;
            if (authMethod == ClientAuthenticationMethods.SelfSignedTlsClientAuth
                || authMethod == ClientAuthenticationMethods.TlsClientAuth
                || request.ClientInfo.TlsClientCertificateBoundAccessTokens)
            {
                thumbprint = Base64Url.EncodeToString(SHA256.HashData(request.ClientCertificate.RawData));
            }
        }

        return authContext with
        {
            Scope = scope,
            Resources = resources,
            CertificateSha256Thumbprint = thumbprint,
            ProofKeyThumbprint = request.ProofKeyThumbprint,
        };
    }
}
