// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using System.Security.Cryptography.X509Certificates;


namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Represents a valid token request along with related authentication and authorization information.
/// </summary>
/// <param name="Model">The token request model containing the information required to process the token request.
/// </param>
/// <param name="AuthorizedGrant">The authorized grant result which encapsulates the result of the authorization
/// process.</param>
/// <param name="ClientInfo">Information about the client making the token request, including client credentials and
/// metadata.</param>
/// /// <param name="Scope">The scopes associated with the token request, indicating the permissions
/// requested by the client. </param>
/// <param name="Resources">The resources associated with the token request,
/// detailing the specific resources the client is requesting access to.</param>
/// <param name="ClientCertificate">The client X.509 certificate presented at the token endpoint for
/// mutual-TLS client authentication (RFC 8705), when applicable; otherwise <c>null</c>.</param>
/// <param name="ProofKeyThumbprint">The RFC 7638 JWK thumbprint of the DPoP proof key bound to the
/// request (RFC 9449 Section 6.1), when the client presented a valid DPoP proof; otherwise <c>null</c>.
/// </param>
/// <param name="PushDeliveryOf">The <c>auth_req_id</c> this request delivers in CIBA push mode, or
/// <c>null</c> for every other caller. It is stated rather than derived: the delivery mode is reachable
/// from <see cref="ClientInfo"/>, but deriving it would put CIBA's rules inside the path every grant
/// type takes, and the push caller holds the identifier anyway. See
/// <see cref="Features.Tokens.PushDeliveryBindings"/> for what it turns into and why the claims are
/// required there and nowhere else.</param>
public record ValidTokenRequest(
    TokenRequest Model,
    AuthorizedGrant AuthorizedGrant,
    ClientInfo ClientInfo,
    ScopeDefinition[] Scope,
    ResourceDefinition[] Resources,
    X509Certificate2? ClientCertificate = null,
    string? ProofKeyThumbprint = null,
    string? PushDeliveryOf = null)
{
    /// <summary>
    /// Builds the validated request from a populated <see cref="TokenValidationContext"/>, taking
    /// the mutual-TLS client certificate (if any) and the DPoP proof-of-possession key
    /// thumbprint (if any) from the populated context.
    /// </summary>
    public ValidTokenRequest(TokenValidationContext context)
        : this(
            context.Request,
            context.AuthorizedGrant,
            context.ClientInfo,
            context.Scope,
            context.Resources,
            context.ClientRequest.ClientCertificate,
            context.ProofKeyThumbprint)
    {
    }
}
