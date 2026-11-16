// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Utils;
using EndSessionRequest = Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The two logout pages the server leaves to its host: asking the end user to confirm a logout no client vouched for,
/// and telling them they are signed out when no client asked to be returned to.
/// </summary>
/// <remarks>
/// The confirmation page sends the request back as it came, with the value the server issued for it, which is how
/// the server learns the end user agreed. Every other answer is the library's own. Each transport adapter answers
/// with its own result type, so each host derives these pages for its adapter and says how a page becomes a result.
/// </remarks>
/// <typeparam name="TResult">The result type of the host's transport adapter.</typeparam>
public abstract class EndSessionPages<TResult>(
    IEndSessionResponseFormatter<TResult> inner,
    IOidcEndpointResolver endpointResolver) : IEndSessionResponseFormatter<TResult>
    where TResult : class
{
    public Task<TResult> FormatResponseAsync(
        EndSessionRequest request, Result<IEndSessionResponse, OidcError> response)
    {
        if (response.TryGetSuccess(out var success))
        {
            switch (success)
            {
                case ConfirmationRequired confirmation:
                    return Task.FromResult(Html(ConfirmationPage(request, confirmation.Confirmation)));

                case EndSessionSuccess { PostLogoutRedirectUri: null, FrontChannelLogoutRequestUris.Count: 0 }:
                    return Task.FromResult(Html(SignedOutPage));
            }
        }

        return inner.FormatResponseAsync(request, response);
    }

    private string ConfirmationPage(EndSessionRequest request, string confirmation)
    {
        var fields = new List<(string Name, string? Value)>
        {
            (EndSessionRequest.Parameters.IdTokenHint, request.IdTokenHint),
            (EndSessionRequest.Parameters.LogoutHint, request.LogoutHint),
            (EndSessionRequest.Parameters.ClientId, request.ClientId),
            (EndSessionRequest.Parameters.PostLogoutRedirectUri, request.PostLogoutRedirectUri?.OriginalString),
            (EndSessionRequest.Parameters.State, request.State),
            (EndSessionRequest.Parameters.Confirmation, confirmation),
        };

        var hidden = string.Concat(fields
            .Where(field => field.Value != null)
            .Select(field =>
                $"<input type=\"hidden\" name=\"{field.Name}\" value=\"{WebUtility.HtmlEncode(field.Value)}\" />"));

        var action = WebUtility.HtmlEncode(endpointResolver.Resolve(OidcEndpoints.EndSession)!.OriginalString);
        return $"""
            <!DOCTYPE html>
            <html>
            <head><title>Sign out</title></head>
            <body>
                <h1>Sign out?</h1>
                <form method="get" action="{action}">
                    {hidden}
                    <button type="submit" id="sign-out" autofocus>Sign out</button>
                </form>
            </body>
            </html>
            """;
    }

    private const string SignedOutPage = """
        <!DOCTYPE html>
        <html>
        <head><title>Signed out</title></head>
        <body><h1>You are signed out</h1></body>
        </html>
        """;

    /// <summary>The adapter's result carrying an HTML page.</summary>
    /// <param name="content">The page.</param>
    protected abstract TResult Html(string content);
}
