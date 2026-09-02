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

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// What one CIBA authentication request asks for.
/// </summary>
/// <remarks>
/// A per-call object rather than configuration: the whole point of this flow is to ask about a particular
/// person, and which person is named differently on every call.
///
/// Only the poll delivery mode is served here. Ping and push have the provider call the client back when the
/// user has answered, which means an application endpoint that anyone can reach and that has to authenticate
/// what arrives - the same shape as back-channel logout, and a separate piece of work. A client registered
/// for poll never sends the client_notification_token those modes require, so the parameter is absent rather
/// than optional.
/// </remarks>
public sealed record BackChannelAuthenticationRequest
{
    /// <summary>
    /// What the eventual tokens are to be good for.
    /// </summary>
    /// <remarks>
    /// REQUIRED, and CIBA section 7.1 goes further than RFC 6749 does: "CIBA authentication requests MUST
    /// therefore contain the openid scope value". Missing it is refused before the request is sent.
    /// </remarks>
    public required IReadOnlyCollection<string> Scopes { get; init; }

    /// <summary>
    /// A hint the provider can resolve to a person, in whatever form it documents.
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// A token carrying the same thing in a form the provider issued and can verify.
    /// </summary>
    public string? LoginHintToken { get; init; }

    /// <summary>
    /// An ID Token this provider issued to this client earlier, naming the person to ask.
    /// </summary>
    public string? IdTokenHint { get; init; }

    /// <summary>
    /// A short message shown to the user on the device that answers, so they can tell which request they are
    /// approving.
    /// </summary>
    public string? BindingMessage { get; init; }

    /// <summary>
    /// A secret the user knows and the provider can check, when the provider is registered to demand one.
    /// </summary>
    public string? UserCode { get; init; }

    /// <summary>
    /// How long the client would like the request to stay open. The provider decides and states its answer.
    /// </summary>
    public TimeSpan? RequestedExpiry { get; init; }

    /// <summary>
    /// The authentication assurance being asked for, most preferred first.
    /// </summary>
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
}
