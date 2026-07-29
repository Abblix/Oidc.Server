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

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest;
using BackChannelAuthenticationSuccess = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess;
using ClientRequest = Abblix.Oidc.Server.Model.ClientRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of a CIBA backchannel authentication request into an <see cref="IResult"/>.</summary>
public interface IBackChannelAuthenticationResponseFormatter
{
    /// <summary>
    /// Formats the backchannel authentication result: a JSON success response, or the RFC-compliant OAuth error
    /// (401 with a <c>WWW-Authenticate</c> challenge, 403, or 400 depending on the failure).
    /// </summary>
    /// <param name="request">The original backchannel authentication request that triggered the response.</param>
    /// <param name="clientRequest">The client request, used to match the <c>WWW-Authenticate</c> scheme on a 401
    /// per RFC 6749 §5.2.</param>
    /// <param name="response">The backchannel authentication result to format.</param>
    Task<IResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest,
        Result<BackChannelAuthenticationSuccess, OidcError> response);
}
