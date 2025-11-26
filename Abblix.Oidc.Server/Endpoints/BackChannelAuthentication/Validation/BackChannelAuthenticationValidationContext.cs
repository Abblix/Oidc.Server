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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Represents the context for validating a backchannel authentication request.
/// This context encapsulates the details of the authentication request, allowing validators to perform
/// the necessary checks and validations according to the backchannel authentication flow.
/// </summary>
/// <param name="Request">
/// The backchannel authentication request that is being validated.
/// This request contains all the parameters and data needed for the validation process.
/// </param>
/// <param name="ClientRequest">
/// The client request associated with the backchannel authentication request. This contains the details of
/// the client making the request, such as client credentials and other relevant information.
/// </param>
public record BackChannelAuthenticationValidationContext(
    BackChannelAuthenticationRequest Request,
    ClientRequest ClientRequest)
{
    private ClientInfo? _clientInfo;

    /// <summary>
    /// Provides information about the client associated with the backchannel authentication request.
    /// This includes the client's identity, credentials, and any attributes relevant to the authentication process.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when attempting to access this property before it has been assigned a value.
    /// </exception>
    public ClientInfo ClientInfo { get => _clientInfo.NotNull(nameof(ClientInfo)); set => _clientInfo = value; }

    /// <summary>
    /// Represents the collection of scope definitions applicable to the authorization request.
    /// These scopes define the permissions and access levels that the client is requesting from
    /// the authorization server.
    /// </summary>
    public ScopeDefinition[] Scope { get; set; } = [];

    /// <summary>
    /// A collection of resource definitions requested as part of the authorization process.
    /// These resources specify the URIs that the client is requesting access to, enhancing the granularity
    /// of resource-level authorization.
    /// </summary>
    public ResourceDefinition[] Resources { get; set; } = [];

    /// <summary>
    /// Represents the login hint token, which is an optional token used to provide hints about the user's identity
    /// to streamline the authentication process.
    /// It may contain pre-validated information, such as a subject identifier.
    /// </summary>
    public JsonWebToken? LoginHintToken { get; set; }

    /// <summary>
    /// Represents the ID token associated with the request, typically used to validate the identity of the user.
    /// This token is issued by the authorization server and can be used for user authentication or as a reference
    /// during token validation.
    /// </summary>
    public JsonWebToken? IdToken { get; set; }

    /// <summary>
    /// Specifies the expiration time for the backchannel authentication request.
    /// This value indicates how long the request is valid before it expires.
    /// </summary>
    public TimeSpan ExpiresIn { get; set; }
}
