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

namespace Abblix.Oidc.Client.Features.Authorization.Context;

/// <summary>
/// Why an authorization response could not be matched to a login this client started.
/// </summary>
/// <remarks>
/// The base package throws on either, and never chooses between them; the choice of what a user is
/// shown needs a request and a redirect, and belongs to the ASP.NET adapter. The distinction is kept
/// so that decision has named cases to switch on, and so a third one - if the seam ever grows one -
/// breaks that switch loudly rather than falling through.
/// </remarks>
public enum AuthorizationStateFailure
{
    /// <summary>
    /// The response carried no <c>state</c> at all.
    /// </summary>
    /// <remarks>
    /// This client sends a <c>state</c> on every request, so a response without one cannot belong to a
    /// login it started: unambiguously malformed or forged, never an ordinary expiry. That it costs
    /// nothing to tell apart is the whole reason it is a separate case from <see cref="Unknown"/>.
    /// </remarks>
    Missing,

    /// <summary>
    /// The response carried a <c>state</c> this client is not holding.
    /// </summary>
    /// <remarks>
    /// Three situations reach here and are deliberately not told apart: the login expired, its state
    /// was already consumed by an earlier callback, or the value was never issued. Separating them
    /// would need the entry, or a marker of its key, to outlive the moment it should have been
    /// discarded - which lengthens the very window
    /// <see cref="AuthorizationStateOptions.Lifetime"/> exists to bound, over a record holding a code
    /// verifier. Such a marker is also an oracle: it answers "was this value ever issued", and for a
    /// replayed response that answer tells whoever captured it that the victim finished signing in.
    /// A browser presenting a genuine <c>state</c> without the cookie that carries the matching ticket
    /// also lands here, which is how a store that binds to the user agent turns login CSRF into this
    /// same indistinguishable miss. The merge is a decision, not an omission.
    /// </remarks>
    Unknown,
}
