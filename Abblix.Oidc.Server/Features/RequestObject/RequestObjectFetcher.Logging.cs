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

using Abblix.Jwt;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.RequestObject;

partial class RequestObjectFetcher
{
    [LoggerMessage(
        EventId = LogEvents.Misc.RequestObjectFetcher.InvalidToken,
        Level = LogLevel.Warning,
        Message = "The request object contains invalid token: {@Error}")]
    private partial void LogInvalidToken(JwtValidationError Error);

    [LoggerMessage(
        EventId = LogEvents.Misc.RequestObjectFetcher.SigningAlgorithmMismatch,
        Level = LogLevel.Warning,
        Message = "The request object for {ClientId} is signed with {Algorithm}, but the client registered {RequiredAlgorithm}")]
    private partial void LogSigningAlgorithmMismatch(string ClientId, string? Algorithm, string RequiredAlgorithm);
}
