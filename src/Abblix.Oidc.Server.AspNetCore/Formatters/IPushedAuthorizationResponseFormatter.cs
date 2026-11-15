// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the response to a pushed authorization request (RFC 9126) into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IPushedAuthorizationResponseFormatter<TResult> where TResult : class
{
    /// <summary>Formats the PAR result (201 with the request URI on success, JSON OAuth error otherwise).</summary>
    Task<TResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response);
}
