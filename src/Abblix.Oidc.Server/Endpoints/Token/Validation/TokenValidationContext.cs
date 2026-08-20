// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Encapsulates the context required for validating token requests, including client and authorization grant details.
/// </summary>
public record TokenValidationContext(TokenRequest Request, ClientRequest ClientRequest)
{
    private ClientInfo? _clientInfo;
    private AuthorizedGrant? _authorizedGrant;

    /// <summary>
    /// Information about the client making the request, derived from the client authentication process.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when trying to access this property before it is set.
    /// </exception>
    public ClientInfo ClientInfo { get => _clientInfo.NotNull(nameof(ClientInfo)); set => _clientInfo = value; }

    /// <summary>
    /// Represents the result of an authorized grant, containing both the session and context of the authorization.
    /// This object is essential for ensuring that the grant is valid and for extracting any additional information
    /// needed for token generation.
    /// </summary>
    /// <remarks>
    /// Asserted by name rather than sworn to with a null-forgiving initialiser, the way <see cref="ClientInfo"/>
    /// beside it already is. The two properties are filled by one pipeline and had been expressing the same fact
    /// in opposite ways, and the readers did not believe the oath: the sender-constraining checks reached this
    /// through a null-conditional, so an unset grant did not fail - it read as "no binding was committed" and
    /// waved the request through. That is the wrong direction for a check whose whole purpose is to refuse a
    /// token redeemed without the key or certificate it was bound to (RFC 9449 section 10, RFC 8705 section 4).
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when trying to access this property before it is set.
    /// </exception>
    public AuthorizedGrant AuthorizedGrant
    {
        get => _authorizedGrant.NotNull(nameof(AuthorizedGrant));
        set => _authorizedGrant = value;
    }

    /// <summary>
    /// Defines the scope of access requested or authorized. This array of scope definitions helps in determining
    /// the extent of access granted to the client and any constraints or conditions applied to the token.
    /// </summary>
    public ScopeDefinition[] Scope { get; set; } = [];

    /// <summary>
    /// Specifies additional resources that the client has requested or that have been included in the authorization.
    /// These definitions provide context on the resources that are accessible with the issued token, enhancing
    /// the token's utility for fine-grained access control.
    /// </summary>
    public ResourceDefinition[] Resources { get; set; } = [];

    /// <summary>
    /// RFC 7638 base64url-encoded JWK thumbprint of the DPoP proof-of-possession key
    /// (RFC 9449 §6.1) populated by the DPoP validator step when a valid proof accompanies
    /// the request. Surfaces to the processor so the issued access token can carry
    /// <c>cnf.jkt</c>. <c>null</c> when no proof was presented or DPoP is not in use.
    /// </summary>
    public string? ProofKeyThumbprint { get; set; }
}
