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
using static Abblix.Utils.HttpServerUtility;


namespace Abblix.Oidc.Server.Features.SessionManagement;
/// <summary>
/// Implements session management functionality in accordance with OpenID Connect session management standards.
/// This service is responsible for managing browser sessions by utilizing cookies and providing mechanisms
/// to check and maintain the session state between the client and the server.
/// </summary>
public class SessionManagementService : ISessionManagementService
{
    private const string CookieNamePlaceHolder = "\"{{cookieName}}\"";

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionManagementService"/> class with the specified
    /// OpenID Connect options and request information provider.
    /// </summary>
    /// <param name="options">The options for configuring the OpenID Connect session management service.</param>
    /// <param name="requestInfoProvider">The provider for accessing request-related information, such as whether
    /// the current request is over HTTPS and the request's base path.</param>
    public SessionManagementService(
        IOptionsSnapshot<OidcOptions> options,
        IRequestInfoProvider requestInfoProvider)
    {
        _options = options;
        _requestInfoProvider = requestInfoProvider;
    }

    private readonly IOptionsSnapshot<OidcOptions> _options;
    private readonly IRequestInfoProvider _requestInfoProvider;

    /// <summary>
    /// Indicates whether session management functionality is enabled based on the configured endpoints.
    /// </summary>
    public bool Enabled => _options.Value.EnabledEndpoints.HasFlag(OidcEndpoints.CheckSession);

    /// <summary>
    /// Retrieves a cookie configured for session management. This cookie can be used to track the session state
    /// between the client and the server.
    /// </summary>
    /// <returns>A <see cref="Cookie"/> object configured with session management settings, such as the cookie name,
    /// domain, path, and security attributes.</returns>
    public Cookie GetSessionCookie()
    {
        var options = _options.Value.CheckSessionCookie;
        return new Cookie(
            options.Name,
            new CookieOptions
            {
                HttpOnly = false,
                IsEssential = true,
                Secure = _requestInfoProvider.IsHttps,
                Path = _requestInfoProvider.PathBase,
                Domain = options.Domain,
                SameSite = options.SameSite,
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
        var hash = UrlTokenEncode(SHA256.HashData(Encoding.UTF8.GetBytes(sessionState)));
        return string.Join(".", hash, salt);
    }

    /// <summary>
    /// Asynchronously generates the response content for the check session endpoint. This method retrieves an HTML template
    /// that includes JavaScript code for the client to check the session state.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation, resulting in a <see cref="CheckSessionResponse"/>
    /// containing the HTML content for the check session iframe and the name of the session management cookie.</returns>
    public async Task<CheckSessionResponse> GetCheckSessionResponseAsync()
    {
        var type = typeof(SessionManagementService);
        var name = $"{type.Namespace}.Resources.checkSession.html";

        string htmlTemplate;
        await using (var stream = type.Assembly.GetManifestResourceStream(name).NotNull(name))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
            htmlTemplate = await reader.ReadToEndAsync();

        var cookieName = _options.Value.CheckSessionCookie.Name;
        var htmlContent = htmlTemplate.Replace(
            CookieNamePlaceHolder,
            JavaScriptStringEncode(cookieName, true));

        return new CheckSessionResponse(htmlContent, cookieName);
    }
}
