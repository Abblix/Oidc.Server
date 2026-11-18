// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Utils;
using EndSessionRequest = Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the result of an RP-initiated logout (end-session) request into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IEndSessionResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the end-session result: a front-channel-logout HTML page, a post-logout redirect, an empty 204, or an
    /// OAuth error.
    /// </summary>
    /// <param name="request">The end-session request as it arrived, its <c>post_logout_redirect_uri</c> unchecked:
    /// the address a successful logout may send the end user to is the one the response carries, and an address the
    /// request names but no client confirms is dropped there.</param>
    /// <param name="response">The end-session response to be formatted.</param>
    Task<TResult> FormatResponseAsync(EndSessionRequest request, Result<IEndSessionResponse, OidcError> response);
}
