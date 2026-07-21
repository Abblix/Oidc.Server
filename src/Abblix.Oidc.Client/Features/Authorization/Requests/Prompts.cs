// Abblix OIDC Client Library
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
/// The values of the <c>prompt</c> parameter this client sends, named as on the wire.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 section 3.1.2.1 defines the full set. Only the one this client sends is named
/// here; the others describe interaction a server-side library has no reason to ask for on the host's
/// behalf.
/// </remarks>
public static class Prompts
{
    /// <summary>
    /// The provider must not display any interface, and answers from the session it already has or refuses.
    /// </summary>
    public const string None = "none";
}
