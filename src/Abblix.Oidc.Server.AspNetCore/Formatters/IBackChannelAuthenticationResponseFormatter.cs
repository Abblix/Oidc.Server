// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest;
using BackChannelAuthenticationSuccess = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess;
using ClientRequest = Abblix.Oidc.Server.Model.ClientRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the result of a CIBA backchannel authentication request into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IBackChannelAuthenticationResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the backchannel authentication result: a JSON success response, or the RFC-compliant OAuth error
    /// (401 with a <c>WWW-Authenticate</c> challenge, 403, or 400 depending on the failure).
    /// </summary>
    /// <param name="request">The original backchannel authentication request that triggered the response.</param>
    /// <param name="clientRequest">The client request, used to match the <c>WWW-Authenticate</c> scheme on a 401
    /// per RFC 6749 section 5.2.</param>
    /// <param name="response">The backchannel authentication result to format.</param>
    Task<TResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest,
        Result<BackChannelAuthenticationSuccess, OidcError> response);
}
