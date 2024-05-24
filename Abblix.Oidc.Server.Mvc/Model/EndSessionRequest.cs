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

using System.Globalization;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.EndSessionRequest.Parameters;


namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a request to end a session, typically used in OpenID Connect logout scenarios.
/// This record encapsulates the necessary parameters for initiating a user logout request.
/// </summary>
public record EndSessionRequest
{
    /// <summary>
    /// The ID token previously issued by the server, used as a hint about the End-User's current authenticated session.
    /// This is typically used to ensure logout requests are associated with the correct user session.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.IdTokenHint)]
    public string? IdTokenHint { get; set; }

    /// <summary>
    /// A hint about the End-User's login identifier used by the client to request logout.
    /// This can be useful for OpenID Providers in determining the relevant user session to end.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.LogoutHint)]
    public string? LogoutHint { get; set; }

    /// <summary>
    /// The client identifier for the application requesting the logout.
    /// This helps the server in identifying which client application is initiating the logout process.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.ClientId)]
    public string? ClientId { get; set; }

    /// <summary>
    /// A value used by the client to maintain state between the logout request and callback.
    /// This can be used to restore the client to the same state it was in before the logout was initiated.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.State)]
    public string? State { get; set; }

    /// <summary>
    /// URI where the user agent is redirected after a logout has been performed.
    /// This URI allows the client to direct the user back to a specific location after logout.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.PostLogoutRedirectUri)]
    public Uri? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Represents the UI locales preferred by the user for the logout page.
    /// This allows clients to request localization of the logout UI based on user's preferences.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.UiLocales)]
    [ModelBinder(typeof(CultureInfoBinder))]
    public CultureInfo[]? UiLocales { get; set; }

    /// <summary>
    /// Indicates whether the logout request has been confirmed by the user.
    /// This is typically used to prevent accidental logouts and ensure intentional user actions.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Confirmed)]
    public bool? Confirmed { get; set; } = false;

    /// <summary>
    /// Maps the properties of this end session request to a <see cref="Core.EndSessionRequest"/> object.
    /// This method is used to translate the request data into a format that can be processed by the core logic of the server.
    /// </summary>
    /// <returns>A <see cref="Core.EndSessionRequest"/> object populated with data from this request.</returns>
    public Core.EndSessionRequest Map()
    {
        return new Core.EndSessionRequest
        {
            ClientId = ClientId,
            UiLocales = UiLocales,
            IdTokenHint = IdTokenHint,
            State = State,
            LogoutHint = LogoutHint,
            PostLogoutRedirectUri = PostLogoutRedirectUri,
            Confirmed = Confirmed,
        };
    }
}
