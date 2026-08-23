// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

partial class RevocationCutoffChecker
{
    // Information rather than Warning: a client presenting a token that a revocation caught is the control
    // working, not a fault. The issue time is what makes the line answer the question an operator actually
    // has - whether this token predates the revocation they wrote, or whether they are looking at a second,
    // later one.
    [LoggerMessage(
        EventId = LogEvents.Revocation.RevocationCutoffChecker.TokenRefusedByCutoff,
        Level = LogLevel.Information,
        Message = "Refused a token issued at {IssuedAt} by a {Scope} revocation cutoff")]
    private partial void LogTokenRefusedByCutoff(RevocationScope Scope, DateTimeOffset IssuedAt);

    // Warning, because this one is a fault: the token is refused without anybody having revoked anything,
    // and the cause is configuration - a rotated pairwise salt, a moved sector identifier, a deleted client.
    // Without this line the refusal is indistinguishable from a real revocation, and the deployment would
    // look for a suspension that was never recorded.
    [LoggerMessage(
        EventId = LogEvents.Revocation.RevocationCutoffChecker.SubjectCouldNotBeResolved,
        Level = LogLevel.Warning,
        Message = "Refused a token of client {ClientId}: its subject could not be resolved, so no revocation "
                  + "cutoff could be ruled out. Check that the client still exists and that its pairwise "
                  + "settings have not changed since the token was issued")]
    private partial void LogSubjectCouldNotBeResolved(Sanitized ClientId);

    // The authorization side of the same control. Without it a revoked user simply stops getting through
    // and nothing says why, which reads as the login being broken rather than as the suspension working.
    //
    // The session identifier is here and the subject is not, deliberately. An operator holding one user's
    // complaint needs to tell that user's refusals from everybody else's, and a line carrying only a scope
    // and an instant cannot do it. The identifier is the narrower of the two handles: it names one sign-in
    // rather than the person across all of them, and it is already what the same user's other log lines
    // carry.
    [LoggerMessage(
        EventId = LogEvents.Revocation.RevocationCutoffChecker.SessionRefusedByCutoff,
        Level = LogLevel.Information,
        Message = "Refused session {SessionId}, authenticated at {AuthenticationTime}, "
                  + "by a {Scope} revocation cutoff")]
    private partial void LogSessionRefusedByCutoff(
        Sanitized SessionId, DateTimeOffset AuthenticationTime, RevocationScope Scope);
}
