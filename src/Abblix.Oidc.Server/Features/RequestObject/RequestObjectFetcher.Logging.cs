// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

    [LoggerMessage(
        EventId = LogEvents.Misc.RequestObjectFetcher.ParametersOutsideRequestObjectIgnored,
        Level = LogLevel.Warning,
        Message = "Strict request-object processing (RFC 9101) ignored these parameters passed outside the request object: {Parameters}")]
    private partial void LogParametersOutsideRequestObjectIgnored(string Parameters);
}
