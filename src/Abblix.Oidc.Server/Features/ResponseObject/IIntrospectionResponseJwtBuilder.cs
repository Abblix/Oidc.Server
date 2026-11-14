// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Encodes a token introspection response into the JWT of RFC 9701 section 5, signed, and encrypted where the
/// resource server asks for it, for the resource server that called the endpoint. The framework-agnostic core of
/// RFC 9701: hosts (MVC, Minimal API, ...) only read the <c>Accept</c> header the request carries and write the
/// result with the <c>application/token-introspection+jwt</c> content type.
/// </summary>
public interface IIntrospectionResponseJwtBuilder
{
    /// <summary>
    /// Builds the JWT introspection response for <paramref name="client"/>.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at; its issuer is the JWT's <c>iss</c>.</param>
    /// <param name="client">The resource server that called the endpoint; its client_id is the JWT's <c>aud</c>, and
    /// its introspection metadata name the algorithms.</param>
    /// <param name="introspectionResponse">The members of the RFC 7662 section 2.2 response, carried as the
    /// <c>token_introspection</c> claim.</param>
    /// <returns>A task that returns the encoded JWT, or a <see cref="Common.NotAcceptableError"/> where no signing key of
    /// the tenant produces the algorithm the response is to be signed with.</returns>
    Task<Result<string, OidcError>> BuildAsync(TenantDefinition tenant, ClientInfo client, JsonObject introspectionResponse);
}
