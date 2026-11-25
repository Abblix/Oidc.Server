// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class ClientAssertionAudience
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.AudienceIsNotOneTheClientMayName,
        Level = LogLevel.Warning,
        Message = "The client assertion for {ClientId} carries the audience {Audience}, which the assertion "
                  + "audiences admitted to it, {Audiences}, do not include; the issuer identifier is "
                  + "{IssuerIdentifier}")]
    private partial void LogAudienceIsNotOneTheClientMayName(
        string ClientId,
        Sanitized Audience,
        ClientAssertionAudiences Audiences,
        string IssuerIdentifier);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.TokenEndpointAudienceAccepted,
        Level = LogLevel.Debug,
        Message = "The client assertion for {ClientId} names the token endpoint URL as its audience, accepted because "
                  + "the client's assertion audiences include it")]
    private partial void LogTokenEndpointAudienceAccepted(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.BackChannelAuthenticationEndpointAudienceAccepted,
        Level = LogLevel.Debug,
        Message = "The client assertion for {ClientId} names the backchannel authentication endpoint URL as its "
                  + "audience, accepted because the client's assertion audiences include it")]
    private partial void LogBackChannelAuthenticationEndpointAudienceAccepted(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.PushedAuthorizationRequestEndpointAudienceAccepted,
        Level = LogLevel.Debug,
        Message = "The client assertion for {ClientId} names the pushed authorization request endpoint URL as its "
                  + "audience, accepted because the client's assertion audiences include it")]
    private partial void LogPushedAuthorizationRequestEndpointAudienceAccepted(string ClientId);
}
