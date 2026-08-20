// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using static System.Web.HttpUtility;
using System.Buffers.Text;


namespace Abblix.Oidc.Server.Features.SessionManagement;
/// <summary>
/// Implements session management functionality in accordance with OpenID Connect session management standards.
/// This service is responsible for managing browser sessions by utilizing cookies and providing mechanisms
/// to check and maintain the session state between the client and the server.
/// </summary>
/// <param name="options">The options for configuring the OpenID Connect session management service.</param>
/// <param name="requestInfoProvider">The provider for accessing request-related information, such as whether
/// the current request is over HTTPS and the request's base path.</param>
public class SessionManagementService(
    IOptionsSnapshot<OidcOptions> options,
    IRequestInfoProvider requestInfoProvider) : ISessionManagementService
{
    private const string CookieNamePlaceHolder = "\"{{cookieName}}\"";

    /// <summary>
    /// Indicates whether session management functionality is enabled based on the configured endpoints.
    /// </summary>
    public bool Enabled => options.Value.EnabledEndpoints.HasFlag(OidcEndpoints.CheckSession);

    /// <summary>
    /// Retrieves a cookie configured for session management. This cookie can be used to track the session state
    /// between the client and the server.
    /// </summary>
    /// <returns>A <see cref="Cookie"/> object configured with session management settings, such as the cookie name,
    /// domain, path, and security attributes.</returns>
    /// <remarks>
    /// Cookie attributes are configured for OpenID Connect Session Management compliance:
    /// <list type="bullet">
    ///     <item><c>HttpOnly = false</c> - Required for check_session_iframe JavaScript to read the cookie</item>
    ///     <item><c>SameSite = None</c> - Required for cross-origin iframe access in Session Management</item>
    ///     <item><c>Secure</c> - Set based on the current request's HTTPS status (required when SameSite=None)</item>
    /// </list>
    /// </remarks>
    public Cookie GetSessionCookie()
    {
        var cookieOptions = options.Value.CheckSessionCookie;
        var path = cookieOptions.Path;

        return new Cookie(
            cookieOptions.Name,
            new()
            {
                HttpOnly = false,
                IsEssential = true,
                Secure = requestInfoProvider.IsHttps,
                Path = !string.IsNullOrEmpty(path) ? path : requestInfoProvider.PathBase,
                Domain = cookieOptions.Domain,
                SameSite = cookieOptions.SameSite,
            });
    }

    /// <summary>
    /// Generates a session state string for an authorization request. This string can be used by the client to
    /// validate the session state.
    /// </summary>
    /// <param name="request">The authorization request containing client and redirect URI information.</param>
    /// <param name="sessionId">A unique identifier for the session.</param>
    /// <returns>A session state string composed of the client ID, origin, session ID, and a salt value, hashed for security.</returns>
    public string GetSessionState(AuthorizationRequest request, string sessionId)
    {
        var origin = request.RedirectUri.NotNull(nameof(request.RedirectUri)).GetOrigin();
        var salt = CryptoRandom.GetRandomBytes(16).ToHexString();
        var sessionState = string.Join(" ", request.ClientId, origin, sessionId, salt);
        var hash = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(sessionState)));
        return string.Join(".", hash, salt);
    }

    /// <summary>
    /// Asynchronously generates the response content for the check session endpoint. This method retrieves an HTML template
    /// that includes JavaScript code for the client to check the session state.
    /// </summary>
    /// <returns>A task that returns a <see cref="CheckSessionResponse"/>
    /// containing the HTML content for the check session iframe and the name of the session management cookie.</returns>
    public async Task<CheckSessionResponse> GetCheckSessionResponseAsync()
    {
        var type = typeof(SessionManagementService);
        var name = $"{type.Namespace}.Resources.checkSession.html";

        string htmlTemplate;
        await using (var stream = type.Assembly.GetManifestResourceStream(name).NotNull(name))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
            htmlTemplate = await reader.ReadToEndAsync();

        var cookieName = options.Value.CheckSessionCookie.Name;
        var htmlContent = htmlTemplate.Replace(
            CookieNamePlaceHolder,
            JavaScriptStringEncode(cookieName, true));

        return new CheckSessionResponse(htmlContent, cookieName);
    }
}
