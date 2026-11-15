// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the result of a dynamic client registration request (RFC 7591) into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IRegisterClientResponseFormatter<TResult> where TResult : class
{
    /// <summary>Formats the registration result (201 with the client configuration on success, OAuth error otherwise).</summary>
    Task<TResult> FormatResponseAsync(
        ClientRegistrationRequest request, Result<ClientRegistrationSuccessResponse, OidcError> response);
}
