// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Vault;

internal sealed partial class LoginClient
{
    [LoggerMessage(LogEvents.TokenLifecycle.LoggedIn, LogLevel.Information,
        "Logged in to Vault via '{Path}': lease {LeaseDuration}, renewable: {Renewable}")]
    private partial void LogLoggedIn(string path, TimeSpan leaseDuration, bool renewable);

    [LoggerMessage(LogEvents.TokenLifecycle.LoginRefused, LogLevel.Warning,
        "Vault refused the login via '{Path}' with {Status}: {Errors}")]
    private partial void LogLoginRefused(string path, int status, string errors);

    [LoggerMessage(LogEvents.TokenLifecycle.LoginUnreachable, LogLevel.Warning,
        "The login via '{Path}' did not reach Vault; it will be retried")]
    private partial void LogLoginUnreachable(string path, Exception exception);

    [LoggerMessage(LogEvents.TokenLifecycle.Renewed, LogLevel.Debug,
        "The Vault token lease was renewed for {LeaseDuration}")]
    private partial void LogRenewed(TimeSpan leaseDuration);

    [LoggerMessage(LogEvents.TokenLifecycle.RenewDenied, LogLevel.Information,
        "Vault denied renewing the token; switching to re-login before the lease ends: {Errors}")]
    private partial void LogRenewDenied(string errors);

    [LoggerMessage(LogEvents.TokenLifecycle.RenewFailed, LogLevel.Warning,
        "Renewing the Vault token failed with {Status}: {Errors}")]
    private partial void LogRenewFailed(int status, string errors);

    [LoggerMessage(LogEvents.TokenLifecycle.RenewUnreachable, LogLevel.Warning,
        "Renewing the Vault token did not reach Vault; it will be retried")]
    private partial void LogRenewUnreachable(Exception exception);

    [LoggerMessage(LogEvents.TokenLifecycle.MalformedAuthResponse, LogLevel.Warning,
        "Vault answered '{Path}' successfully but without a usable auth block")]
    private partial void LogMalformedAuthResponse(string path);
}
