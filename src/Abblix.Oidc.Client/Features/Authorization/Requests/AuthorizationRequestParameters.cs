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

namespace Abblix.Oidc.Client.Features.Authorization.Requests;

/// <summary>
/// What this particular login asks of the provider, over and above the client's standing configuration.
/// </summary>
/// <remarks>
/// These parameters belong to a single request rather than to the client, which is why they arrive here and
/// not in <see cref="AuthorizationRequestOptions"/>: the account being hinted at, the assurance being demanded
/// for a step-up, the screen the user is standing in front of, all change from one login to the next while the
/// redirect address and the flow do not. A host that wants the same value on every request can supply it on
/// every call, but the reverse is not available if these live in configuration.
/// Everything here is optional, and every member left unset is a parameter this client does not send at all.
/// That is the honest default: an omitted OpenID Connect request parameter means "no preference", while a
/// present one with an empty value is a malformed request.
/// </remarks>
public sealed record AuthorizationRequestParameters
{
    /// <summary>
    /// How much time may have passed since the end user last actively authenticated.
    /// </summary>
    /// <remarks>
    /// OIDC Core 1.0 section 3.1.2.1 marks <c>max_age</c> OPTIONAL, and adds the obligation that makes it
    /// enforceable: "When max_age is used, the ID Token returned MUST include an auth_time Claim Value."
    /// Asking therefore also arms a check, and this client refuses a token that omits the claim rather than
    /// treating the omission as permission.
    /// </remarks>
    public TimeSpan? MaxAge { get; init; }

    /// <summary>
    /// The authentication context class references this login will accept, most specific first.
    /// </summary>
    /// <remarks>
    /// OIDC Core 1.0 section 3.1.2.1 marks <c>acr_values</c> OPTIONAL and sends them space-separated, in
    /// order of preference. The specification places the meaning of the values outside its own scope, so
    /// this client compares the asserted value against this set and claims nothing about which of them is
    /// stronger: there is no ordering to appeal to.
    /// </remarks>
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];

    /// <summary>
    /// Which login identifier the end user is expected to use, if the provider needs to ask.
    /// </summary>
    /// <remarks>
    /// A hint and nothing more: OIDC Core 1.0 section 3.1.2.1 leaves the provider free to ignore it, and
    /// nothing in the response confirms it was honoured. Do not treat it as a way to select an account.
    /// </remarks>
    public string? LoginHint { get; init; }

    /// <summary>
    /// How the provider should present its pages, from the values in <see cref="Displays"/>.
    /// </summary>
    public string? Display { get; init; }

    /// <summary>
    /// What the provider must or must not do about interacting with the end user, from the values in
    /// <see cref="Prompts"/>.
    /// </summary>
    /// <remarks>
    /// A set rather than a flag, because the parameter is a space-delimited list and the values compose.
    /// One combination does not: OIDC Core 1.0 section 3.1.2.1 says that if the parameter "contains none
    /// with any other value, an error is returned", so this client refuses that pairing before the browser
    /// leaves rather than letting the user make the trip to learn it.
    /// </remarks>
    public IReadOnlyCollection<string> Prompt { get; init; } = [];

    /// <summary>
    /// The claims this login requests, as the JSON object defined by OIDC Core 1.0 section 5.5.
    /// </summary>
    /// <remarks>
    /// Carried as text and sent verbatim. The parameter's shape is an object with <c>userinfo</c> and
    /// <c>id_token</c> members whose contents are open-ended, and a typed model here would have to choose
    /// which extensions to admit; the value is the caller's to compose. Note the parameter is defined in
    /// section 5.5 rather than alongside its neighbours in 3.1.2.1.
    /// </remarks>
    public string? Claims { get; init; }
}
