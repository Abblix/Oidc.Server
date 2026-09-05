// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

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
    /// A <see cref="Task"/> that, when completed successfully, results in an <see cref="IntrospectionSuccess"/>
    /// or an <see cref="OidcError"/>. The success response contains information about the token's current state,
    /// such as whether it is active, and potentially other metadata. In case of an invalid request,
    /// the error response will detail the reasons for rejection.
    /// </returns>
    /// <remarks>
    /// Implementations of this interface play a critical role in the security of OAuth 2.0 and OIDC systems
    /// by enabling resource servers and other relying parties to verify the validity and metadata of tokens.
    /// This helps prevent unauthorized access and ensures that tokens are used in accordance with their
    /// intended scopes and lifetimes.
    /// </remarks>
    Task<Result<IntrospectionSuccess, OidcError>> HandleAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest);
}
