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
