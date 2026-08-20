// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Microsoft.AspNetCore.Http;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the response to a pushed authorization request (RFC 9126) into an <see cref="IResult"/>.</summary>
public interface IPushedAuthorizationResponseFormatter
{
    /// <summary>Formats the PAR result (201 with the request URI on success, JSON OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response);
}
