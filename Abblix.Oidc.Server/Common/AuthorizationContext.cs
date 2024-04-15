// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents the context of an authorization process, encapsulating key parameters necessary for processing
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
public record AuthorizationContext(string ClientId, string[] Scope, RequestedClaims? RequestedClaims)
{
    /// <summary>
    /// The unique identifier for the client making the authorization request, as registered in the authorization server.
    /// This identifier is crucial for linking the authorization request and the issued tokens to a specific client application.
    /// </summary>
    public string ClientId { get; init; } = ClientId;

    /// <summary>
    /// Defines the scope of access requested by the client. Scopes are used to specify the level of access or permissions
    /// that the client is requesting on the user's behalf. They play a key role in enforcing principle of least privilege.
    /// </summary>
    public string[] Scope { get; init; } = Scope;

    /// <summary>
    /// Optional. Specifies the individual Claims requested by the client, providing detailed instructions
    /// for the authorization server on the Claims to be returned, either in the ID Token or via the UserInfo endpoint.
    /// This mechanism supports clients in obtaining consented user information in a structured and controlled manner.
    /// </summary>
    public RequestedClaims? RequestedClaims { get; init; } = RequestedClaims;

    /// <summary>
    /// The URI where the authorization response should be sent. This URI must match one of the registered redirect URIs
    /// for the client application, ensuring that authorization responses are delivered to the correct destination securely.
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
}
