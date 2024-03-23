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

namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Defines the contract for handling introspection requests to determine the current state and validity of
/// OAuth 2.0 tokens, such as access tokens or refresh tokens.
/// </summary>
public interface IIntrospectionHandler
{
    /// <summary>
    /// Asynchronously processes an introspection request, validating its authorization and the token in question,
    /// and then returning the token's state and other relevant information.
    /// </summary>
    /// <param name="introspectionRequest">The introspection request containing the token and possibly other parameters
    /// required for validating the request and introspecting the token.</param>
    /// <param name="clientRequest">Additional information about the client making the request, which may be necessary
    /// for validating the request in certain contexts.</param>
    /// <returns>
    /// A <see cref="Task"/> that, when completed successfully, results in an <see cref="IntrospectionResponse"/>.
    /// This response contains information about the token's current state, such as whether it is active,
    /// and potentially other metadata. In case of an invalid request,
    /// the response will detail the reasons for rejection.
    /// </returns>
    /// <remarks>
    /// Implementations of this interface play a critical role in the security of OAuth 2.0 and OIDC systems
    /// by enabling resource servers and other relying parties to verify the validity and metadata of tokens.
    /// This helps prevent unauthorized access and ensures that tokens are used in accordance with their
    /// intended scopes and lifetimes.
    /// </remarks>
    Task<IntrospectionResponse> HandleAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest);
}
