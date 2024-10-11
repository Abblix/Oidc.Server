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

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents the context of an authorization process, encapsulating the key parameters required for processing
/// authorization requests.
/// </summary>
/// <remarks>
/// This record is pivotal for tracking the state of an authorization request throughout its lifecycle.
/// It encapsulates details that are critical for the secure issuance of authorization codes and tokens,
/// while ensuring compliance with OAuth 2.0 and OpenID Connect protocols. The context facilitates
/// not just the validation of requests at the token endpoint, but also supports secure interactions
/// by incorporating mechanisms like PKCE and nonce values to mitigate common attack vectors such as
/// code injection and replay attacks. Furthermore, it carries information about requested scopes and claims,
/// enabling fine-grained access control and personalized identity assertion in accordance with the client's needs
/// and the authorization server's policies.
/// </remarks>
public record AuthorizationContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationContext"/> class.
    /// </summary>
    /// <param name="clientId">
    /// The unique identifier of the client making the authorization request.
    /// </param>
    /// <param name="scope">
    /// An array of scope values requested by the client, representing the access permissions being sought.
    /// </param>
    /// <param name="requestedClaims">
    /// Optional claims that the client is requesting as part of the authorization process,
    /// providing additional information about the user's identity.
    /// </param>
    [JsonConstructor]
    public AuthorizationContext(string clientId, string[] scope, RequestedClaims? requestedClaims)
    {
        ClientId = clientId;
        Scope = scope;
        RequestedClaims = requestedClaims;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationContext"/> class with a client ID,
    /// a collection of scopes, and optional requested claims.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client making the authorization request.</param>
    /// <param name="scopes">An array of scope definitions requested by the client.</param>
    /// <param name="resources">An array of resource definitions associated with the authorization request.</param>
    /// <param name="requestedClaims">Optional claims requested by the client for the authorization process.</param>
    public AuthorizationContext(
        string clientId,
        ScopeDefinition[] scopes,
        ResourceDefinition[] resources,
        RequestedClaims? requestedClaims)
        : this(clientId, GetScopeNames(scopes, resources), requestedClaims)
    {
        Resources = Array.ConvertAll(resources, resource => resource.Resource);
    }

    /// <summary>
    /// Extracts unique scope names from the provided scope and resource definitions.
    /// This method aggregates scopes defined in both scopes and resources to ensure
    /// there are no duplicates, returning them as an array of strings.
    /// </summary>
    /// <param name="scopes">An array of scope definitions to extract names from.</param>
    /// <param name="resources">An array of resource definitions to extract names from.</param>
    /// <returns>
    /// An array of unique scope names represented as strings, combining those from scopes
    /// and resources.
    /// </returns>
    private static string[] GetScopeNames(ScopeDefinition[] scopes, ResourceDefinition[] resources)
    {
        return scopes
            .Concat(resources.SelectMany(rd => rd.Scopes))
            .Select(sd => sd.Scope)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// The unique identifier for the client making the authorization request, as registered in the authorization server.
    /// This identifier is crucial for linking the authorization request and the issued tokens to a specific
    /// client application.
    /// </summary>
    public string ClientId { get; init; }

    /// <summary>
    /// Defines the scope of access requested by the client. Scopes are used to specify the level of access or
    /// permissions that the client is requesting on the user's behalf.
    /// They play a key role in enforcing the principle of least privilege.
    /// </summary>
    public string[] Scope { get; init; }

    /// <summary>
    /// Optional. Specifies the individual Claims requested by the client, providing detailed instructions
    /// for the authorization server on the Claims to be returned, either in the ID Token or via the UserInfo endpoint.
    /// </summary>
    public RequestedClaims? RequestedClaims { get; init; }

    /// <summary>
    /// The URI where the authorization response should be sent. This URI must match one of the registered redirects URI
    /// for the client application, ensuring that authorization responses are delivered to the correct destination
    /// securely.
    /// </summary>
    public Uri? RedirectUri { get; init; }

    /// <summary>
    /// A string value used to associate a client session with an ID Token, mitigating replay attacks by ensuring
    /// that an ID Token cannot be used in a different context than the one it was intended for.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The high-entropy cryptographic string provided by the client, used in the PKCE (Proof Key for Code Exchange)
    /// extension to secure the exchange of the authorization code for a token,
    /// especially in public clients and mobile applications.
    /// </summary>
    public string? CodeChallenge { get; init; }

    /// <summary>
    /// Specifies the transformation method applied to the 'code_verifier' when generating the 'code_challenge',
    /// enhancing the security of PKCE by allowing the authorization server to verify the code exchange authenticity.
    /// </summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// The resources for which the authorization is granted.
    /// These resources are typically URIs that identify specific services or data that the client is authorized
    /// to access.
    /// </summary>
    public Uri[]? Resources { get; init; }

    public void Deconstruct(out string ClientId, out string[] Scope, out RequestedClaims? RequestedClaims)
    {
        ClientId = this.ClientId;
        Scope = this.Scope;
        RequestedClaims = this.RequestedClaims;
    }
}
