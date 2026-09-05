// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using EndSessionRequest = Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// Decorates <see cref="IEndSessionResponseFormatter"/> to delete the session-management cookie when session management
/// is enabled, so the browser's logged-in state is cleared as part of logout.
/// </summary>
public class EndSessionResponseFormatterDecorator(
    IEndSessionResponseFormatter inner,
    ISessionManagementService sessionManagementService) : IEndSessionResponseFormatter
{
    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(
        EndSessionRequest request, Result<EndSessionSuccess, OidcError> response)
    {
        var result = await inner.FormatResponseAsync(request, response);

        if (sessionManagementService.Enabled)
        {
            var cookie = sessionManagementService.GetSessionCookie();
            result = result.WithDeleteCookie(cookie.Name, cookie.Options.ConvertOptions());
        }

        return result;
    }
}
