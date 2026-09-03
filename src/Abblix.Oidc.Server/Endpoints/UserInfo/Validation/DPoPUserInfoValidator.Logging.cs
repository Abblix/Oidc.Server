// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Validation;

partial class DPoPUserInfoValidator
{
    /// <inheritdoc/>
    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPUserInfoValidator.NonceChallengeIssued,
        Level = LogLevel.Debug,
        Message = "DPoP nonce challenge issued from UserInfo endpoint (use_dpop_nonce). Triggered by missing or stale nonce in proof.")]
    protected override partial void LogNonceChallengeIssued();

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPUserInfoValidator.ProofRequiredButMissing,
        Level = LogLevel.Information,
        Message = "DPoP proof required at UserInfo endpoint but missing ({TriggerReason}).")]
    private partial void LogProofRequiredButMissing(string triggerReason);

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPUserInfoValidator.ProofKeyMismatch,
        Level = LogLevel.Information,
        Message = "DPoP proof key thumbprint {ActualThumbprint} does not match access-token cnf.jkt {CommittedThumbprint} (RFC 9449 section 6.1).")]
    private partial void LogProofKeyMismatch(string committedThumbprint, string actualThumbprint);

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPUserInfoValidator.ProofRejected,
        Level = LogLevel.Information,
        Message = "DPoP proof rejected at UserInfo endpoint: {Reason}.")]
    private partial void LogProofRejected(string reason);

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPUserInfoValidator.SchemeBindingMismatch,
        Level = LogLevel.Warning,
        Message = "Authorization scheme/binding mismatch at UserInfo endpoint: presented scheme={PresentedScheme}, access-token DPoP-bound={TokenIsBound} (RFC 9449 section 7.1).")]
    private partial void LogSchemeBindingMismatch(string presentedScheme, bool tokenIsBound);
}
