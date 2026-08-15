// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
