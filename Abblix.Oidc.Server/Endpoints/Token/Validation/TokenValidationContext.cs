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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Encapsulates the context required for validating token requests, including client and authorization grant details.
/// </summary>
public record TokenValidationContext(TokenRequest Request, ClientRequest ClientRequest)
{
    /// <summary>
    /// Information about the client making the request, derived from the client authentication process.
    /// </summary>
    public ClientInfo ClientInfo { get; set; }

    /// <summary>
    /// Represents the result of an authorized grant, containing both the session and context of the authorization.
    /// This object is essential for ensuring that the grant is valid and for extracting any additional information
    /// needed for token generation.
    /// </summary>
    public AuthorizedGrant AuthorizedGrant { get; set; }

    /// <summary>
    /// Defines the scope of access requested or authorized. This array of scope definitions helps in determining
    /// the extent of access granted to the client and any constraints or conditions applied to the token.
    /// </summary>
    public ScopeDefinition[] Scope { get; set; } = Array.Empty<ScopeDefinition>();

    /// <summary>
    /// Specifies additional resources that the client has requested or that have been included in the authorization.
    /// These definitions provide context on the resources that are accessible with the issued token, enhancing
    /// the token's utility for fine-grained access control.
    /// </summary>
    public ResourceDefinition[] Resources { get; set; } = Array.Empty<ResourceDefinition>();
}
