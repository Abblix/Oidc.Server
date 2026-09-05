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
using Microsoft.AspNetCore.Http;
using EndSessionRequest = Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of an RP-initiated logout (end-session) request into an <see cref="IResult"/>.</summary>
public interface IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats the end-session result: a front-channel-logout HTML page, a post-logout redirect, an empty 204, or an
    /// OAuth error.
    /// </summary>
    Task<IResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, OidcError> response);
}
