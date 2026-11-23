// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// The address the user agent is sent to when the end user has to be asked whether to log out: the tenant's
/// confirmation page, carrying everything the page sends back to the end-session endpoint with their answer.
/// </summary>
/// <remarks>
/// The page gets the request's own parameters rather than a reference to a stored copy, because the end-session
/// endpoint reads its request from these parameters alone, and the value the server issued for the question is what
/// makes the request that carries them back an answer. Each transport adapter resolves the page's address its own way
/// and builds the address from this one place.
/// </remarks>
internal static class LogoutConfirmationPage
{
    /// <summary>
    /// The confirmation page with the parameters of the logout request and the value issued for the question.
    /// </summary>
    /// <param name="page">The tenant's confirmation page, resolved to an absolute address.</param>
    /// <param name="request">The logout request the end user is asked about.</param>
    /// <param name="confirmation">The value the page sends back with the end user's answer.</param>
    public static string Address(Uri page, EndSessionRequest request, string confirmation)
        => page.AddToQuery(
        [
            (EndSessionRequest.Parameters.IdTokenHint, request.IdTokenHint),
            (EndSessionRequest.Parameters.LogoutHint, request.LogoutHint),
            (EndSessionRequest.Parameters.ClientId, request.ClientId),
            (EndSessionRequest.Parameters.PostLogoutRedirectUri, request.PostLogoutRedirectUri?.OriginalString),
            (EndSessionRequest.Parameters.State, request.State),
            (EndSessionRequest.Parameters.UiLocales, request.UiLocales is { } locales
                ? string.Join(' ', locales.Select(locale => locale.Name))
                : null),
            (EndSessionRequest.Parameters.Confirmation, confirmation),
        ]);
}
