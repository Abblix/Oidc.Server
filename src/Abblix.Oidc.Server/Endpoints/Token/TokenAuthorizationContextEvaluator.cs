// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using System.Security.Cryptography;

using System.Buffers.Text;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Default <see cref="ITokenAuthorizationContextEvaluator"/>: narrows the originally granted scope and
/// resource sets to the intersection with what the token request asks for (RFC 6749 section 6 / RFC 8707 section 2.2),
/// and, for a client registered for certificate-bound access tokens or held to a profile issuing no other, derives the
/// RFC 8705 section 3 <c>cnf.x5t#S256</c> thumbprint of the certificate presented over mutual TLS to bind the issued
/// tokens.
/// </summary>
public class TokenAuthorizationContextEvaluator : ITokenAuthorizationContextEvaluator
{
    /// <inheritdoc />
    public AuthorizationContext EvaluateAuthorizationContext(TenantDefinition tenant, ValidTokenRequest request)
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
        // Certificate-bound confirmation thumbprint (RFC 8705 section 3): preserve the binding the
        // grant already carries. RFC 8705 section 4 says the AS SHOULD keep a refreshed token bound to
        // the original certificate and check that binding, so an existing thumbprint is never
        // overwritten - neither dropped when no certificate is re-presented on refresh, nor
        // rebound to a rotated certificate. A fresh thumbprint is computed only at initial
        // issuance (no prior binding), for a client its registration or profile binds. A client so bound that
        // presents no certificate gets an unbound token: RFC 8705 section 3.4 leaves "an error or ... an
        // unbound token" to the server, and a profile requiring a sender-constrained token refuses it earlier.
        var thumbprint = authContext.CertificateSha256Thumbprint;
        if (thumbprint == null &&
            request.ClientCertificate != null &&
            CertificateBoundAccessTokens.AreIssuedTo(
                request.ClientInfo,
                SecurityProfileRequirements.For(request.ClientInfo, tenant.DefaultSecurityProfile)))
        {
            thumbprint = Base64Url.EncodeToString(SHA256.HashData(request.ClientCertificate.RawData));
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
