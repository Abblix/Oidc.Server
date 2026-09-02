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

namespace Abblix.Oidc.Client.Features.SessionManagement;

/// <summary>
/// Everything a page needs in order to watch whether the end-user is still logged in at the provider.
/// </summary>
/// <remarks>
/// The watching itself happens in the browser and cannot happen anywhere else: OpenID Connect Session
/// Management 1.0 section 3.1 has the RP load an invisible frame that "polls the OP iframe with postMessage
/// at an interval suitable for the RP application", and section 3.2 has the provider's frame answer
/// <c>changed</c>, <c>unchanged</c> or <c>error</c>. A server-side library has no part in that conversation.
/// What it can do is hand the page the three values that conversation needs, spelled correctly, so they are
/// not assembled by hand in a template.
/// Two duties stay with whoever writes that page, and both are in section 6: the RP frame "MUST enforce that
/// it only processes messages from the origin of the OP frame", and it "MUST reject postMessage requests
/// from any other source origin to prevent cross-site scripting attacks". Nothing here can enforce that on
/// its behalf.
/// </remarks>
/// <param name="CheckSessionIframe">
/// The provider's frame to poll, as published in its metadata.
/// </param>
/// <param name="ClientId">This client's identifier, which the message names.</param>
/// <param name="SessionState">
/// The login state from the most recent authorization response. Opaque, and replaced at every login.
/// </param>
public sealed record SessionCheck(string CheckSessionIframe, string ClientId, string SessionState)
{
    /// <summary>
    /// The message the RP frame posts to the provider's frame.
    /// </summary>
    /// <remarks>
    /// Section 3.1 defines it exactly: "The postMessage from the RP iframe delivers the following
    /// concatenation as the data: Client ID + ' ' + Session State". A single space, and the reason it is
    /// built here rather than in a template is that section 2 also says the session state "MUST NOT contain
    /// the space character" - so the separator is the only space in the message, and a stray one produces a
    /// message the provider reads as a different client.
    /// </remarks>
    public string Message => $"{ClientId} {SessionState}";
}
