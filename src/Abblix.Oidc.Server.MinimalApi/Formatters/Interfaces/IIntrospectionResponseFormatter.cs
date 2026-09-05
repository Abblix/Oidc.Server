// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using IntrospectionRequest = Abblix.Oidc.Server.Model.IntrospectionRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of a token introspection request into an <see cref="IResult"/>.</summary>
public interface IIntrospectionResponseFormatter
{
    /// <summary>Formats the introspection result (RFC 7662 JSON or RFC 9701 JWT on success, OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(IntrospectionRequest request, Result<IntrospectionSuccess, OidcError> response);
}
