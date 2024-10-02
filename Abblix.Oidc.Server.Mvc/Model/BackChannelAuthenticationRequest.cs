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

using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Model;


/// <summary>
/// Represents a client-initiated backchannel authentication request, typically used in the CIBA (Client-Initiated
/// Backchannel Authentication) flow as part of OpenID Connect. This request allows a client to request user
/// authentication through a backchannel communication, which involves the authorization server interacting with
/// the user asynchronously.
/// </summary>
public record BackChannelAuthenticationRequest
{
    /// <summary>
    /// A space-separated list of scopes requested by the client. Scopes define the level of access requested by
    /// the client and the types of information that the client wants to retrieve from the user's account.
    /// </summary>
    [BindProperty(Name = Parameters.Scope)]
    [ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[] Scope { get; init; } = Array.Empty<string>();

    /// <summary>
    /// A token issued by the client that the authorization server uses to notify the client about the result
    /// of the authentication request. This token allows the authorization server to securely deliver
    /// the authentication result to the client.
    /// </summary>
    [BindProperty(Name = Parameters.ClientNotificationToken)]
    public string? ClientNotificationToken { get; init; }

    /// <summary>
    /// A list of requested Authentication Context Class References (ACRs) that the client wishes to be used
    /// for authentication. ACR values indicate the level of authentication strength required,
    /// such as multifactor authentication or biometric verification.
    /// </summary>
    [BindProperty(Name = Parameters.AcrValues)]
    public List<string>? AcrValues { get; init; }

    /// <summary>
    /// A token used to pass a hint about the login identifier to the authorization server.
    /// This token is typically used to identify the user for the authentication process.
    /// </summary>
    [BindProperty(Name = Parameters.LoginHintToken)]
    public string? LoginHintToken { get; init; }

    /// <summary>
    /// An ID token previously issued to the client, used as a hint to identify the user for authentication.
    /// The ID token hint can be used by the authorization server to verify the user's identity without
    /// requiring re-authentication.
    /// </summary>
    [BindProperty(Name = Parameters.IdTokenHint)]
    public string? IdTokenHint { get; init; }

    /// <summary>
    /// A hint about the user's login identifier (such as email or username), used by the authorization server
    /// to identify the user for authentication. This can help streamline the authentication process
    /// by pre-filling the user's information.
    /// </summary>
    [BindProperty(Name = Parameters.LoginHint)]
    public string? LoginHint { get; init; }

    /// <summary>
    /// A human-readable message intended to be shown to the user, providing context or instructions for
    /// the authentication process.
    /// This message is often used to help the user understand the purpose of the authentication request.
    /// </summary>
    [BindProperty(Name = Parameters.BindingMessage)]
    public string? BindingMessage { get; init; }

    /// <summary>
    /// A user code provided by the user, typically as a reference for the authentication request.
    /// This code is often used in scenarios where the user is identified by a code that they provide to the client.
    /// </summary>
    [BindProperty(Name = Parameters.UserCode)]
    public string? UserCode { get; init; }

    /// <summary>
    /// An optional parameter that specifies the requested expiry time for the authentication request.
    /// This defines how long the authentication request remains valid before it expires.
    /// </summary>
    [BindProperty(Name = Parameters.RequestedExpiry)]
    [ModelBinder(typeof(SecondsToTimeSpanModelBinder))]
    public TimeSpan? RequestedExpiry { get; init; }

    /// <summary>
    /// Specifies the resource for which the access token is requested.
    /// As defined in RFC 8707, this parameter is used to request access tokens with a specific scope for a particular
    /// resource.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.Resource)]
    public Uri[]? Resources { get; set; }

    /// <summary>
    /// Maps the properties of this back-channel authentication request to a corresponding
    /// <see cref="Server.Model.BackChannelAuthenticationRequest"/> object. This mapping facilitates
    /// the processing of the request in the core layers of the authentication framework.
    /// </summary>
    /// <returns>
    /// A <see cref="Server.Model.BackChannelAuthenticationRequest"/> object populated with the relevant
    /// data from this request.
    /// </returns>
    public Core.BackChannelAuthenticationRequest Map()
    {
        return new Core.BackChannelAuthenticationRequest
        {
            Scope = Scope,
            ClientNotificationToken = ClientNotificationToken,
            AcrValues = AcrValues,
            LoginHintToken = LoginHintToken,
            IdTokenHint = IdTokenHint,
            LoginHint = LoginHint,
            BindingMessage = BindingMessage,
            UserCode = UserCode,
            RequestedExpiry = RequestedExpiry,
            Resources = Resources,
        };
    }

    public static class Parameters
    {
        public const string Scope = "scope";
        public const string ClientNotificationToken = "client_notification_token";
        public const string AcrValues = "acr_values";
        public const string LoginHintToken = "login_hint_token";
        public const string IdTokenHint = "id_token_hint";
        public const string LoginHint = "login_hint";
        public const string BindingMessage = "binding_message";
        public const string UserCode = "user_code";
        public const string RequestedExpiry = "requested_expiry";
        public const string Resource = "resource";
    }
}
