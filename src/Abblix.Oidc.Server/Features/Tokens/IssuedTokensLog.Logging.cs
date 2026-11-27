// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

internal sealed partial class IssuedTokensLog
{
    [SuppressMessage("SonarQube", "S107:Methods should not have too many parameters",
        Justification = "Each parameter is a structured field of the record, one per placeholder of the message: grouped into an object, the fields would reach the log as one formatted string.")]
    [LoggerMessage(
        EventId = LogEvents.TokenIssuance.IssuedTokensLog.TokensIssued,
        Level = LogLevel.Information,
        Message = "Tenant {TenantId} issued {Tokens} to client {ClientId} for subject {Subject} under grant type " +
                  "{GrantType} and grant {GrantId}, with scope {Scope} for audiences {Audiences}")]
    private partial void LogTokensIssued(
        string TenantId,
        string[] Tokens,
        Sanitized ClientId,
        Fingerprint Subject,
        Sanitized GrantType,
        Sanitized GrantId,
        Sanitized[] Scope,
        Sanitized[] Audiences);

    [LoggerMessage(
        EventId = LogEvents.TokenIssuance.IssuedTokensLog.FrontChannelTokensIssued,
        Level = LogLevel.Information,
        Message = "Tenant {TenantId} issued {Tokens} through the front channel to client {ClientId} for subject " +
                  "{Subject} under grant type {GrantType}, with scope {Scope} for audiences {Audiences}")]
    private partial void LogFrontChannelTokensIssued(
        string TenantId,
        string[] Tokens,
        Sanitized ClientId,
        Fingerprint Subject,
        string GrantType,
        Sanitized[] Scope,
        Sanitized[] Audiences);
}
