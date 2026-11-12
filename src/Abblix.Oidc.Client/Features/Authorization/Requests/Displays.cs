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
/// The values OIDC Core 1.0 section 3.1.2.1 defines for the <c>display</c> authorization request parameter,
/// which tells the provider how to present its authentication and consent pages.
/// </summary>
/// <remarks>
/// Unlike <see cref="Prompts"/>, this parameter carries a single value rather than a list, and it is advisory
/// throughout: nothing in the response reports which presentation the provider chose, so a client cannot
/// verify that its request was honoured and must not depend on it.
/// The set is closed by the specification, which is why these are constants rather than free text. It is also
/// showing its age: <c>wap</c> names a feature phone browser, and is kept because the specification lists it.
/// </remarks>
public static class Displays
{
    /// <summary>
    /// A full page in the user agent, which is what a provider does when asked for nothing in particular.
    /// </summary>
    public const string Page = "page";

    /// <summary>
    /// A popup window, sized for a dialogue rather than a page.
    /// </summary>
    public const string Popup = "popup";

    /// <summary>
    /// A presentation suited to a device with a touch interface.
    /// </summary>
    public const string Touch = "touch";

    /// <summary>
    /// A presentation suited to a feature phone.
    /// </summary>
    public const string Wap = "wap";
}
