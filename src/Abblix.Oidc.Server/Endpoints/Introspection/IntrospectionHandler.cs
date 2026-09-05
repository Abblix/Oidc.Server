// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Manages the processing of token introspection requests according to OAuth 2.0 specifications, facilitating
/// the validation and introspection of tokens to determine their current state and metadata.
/// </summary>
/// <param name="validator">An implementation of <see cref="IIntrospectionRequestValidator"/> tasked with
/// validating introspection requests against OAuth 2.0 standards.</param>
/// <param name="processor">An implementation of <see cref="IIntrospectionRequestProcessor"/> responsible
/// for processing validated introspection requests and retrieving token information.</param>
public class IntrospectionHandler(
    IIntrospectionRequestValidator validator,
    IIntrospectionRequestProcessor processor) : IIntrospectionHandler
{
    /// <summary>
    /// Asynchronously handles an introspection request by validating the request and, if valid, processing it to
    /// return the state and metadata of the specified token.
    /// </summary>
    /// <param name="introspectionRequest">The introspection request containing the token to be introspected and
    /// other relevant parameters.</param>
    /// <param name="clientRequest">Supplementary information about the client making the request,
    /// useful for contextual validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to an <see cref="IntrospectionSuccess"/>, which includes the token's
    /// active status and potentially other metadata, or an <see cref="OidcError"/> if the request is invalid.
    /// </returns>
    /// <remarks>
    /// Implementations of this method are crucial for maintaining the integrity and security of token-based
    /// authentication systems by allowing resource servers and other entities to verify the validity
    /// and attributes of tokens.
    /// </remarks>
    public async Task<Result<IntrospectionSuccess, OidcError>> HandleAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(introspectionRequest, clientRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
