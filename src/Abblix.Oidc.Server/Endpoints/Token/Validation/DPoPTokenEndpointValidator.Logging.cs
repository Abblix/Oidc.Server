// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

partial class DPoPTokenEndpointValidator
{
    /// <inheritdoc/>
    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPTokenEndpointValidator.NonceChallengeIssued,
        Level = LogLevel.Debug,
        Message = "DPoP nonce challenge issued from token endpoint (use_dpop_nonce). Triggered by missing or stale nonce in proof.")]
    protected override partial void LogNonceChallengeIssued();

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPTokenEndpointValidator.ProofRequiredButMissing,
        Level = LogLevel.Information,
        Message = "DPoP proof required at token endpoint but missing ({TriggerReason}).")]
    private partial void LogProofRequiredButMissing(string triggerReason);

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPTokenEndpointValidator.ProofKeyMismatch,
        Level = LogLevel.Information,
        Message = "DPoP proof key thumbprint {ActualThumbprint} does not match committed dpop_jkt {CommittedThumbprint} (RFC 9449 §10).")]
    private partial void LogProofKeyMismatch(string committedThumbprint, string actualThumbprint);

    [LoggerMessage(
        EventId = LogEvents.DPoP.DPoPTokenEndpointValidator.ProofRejected,
        Level = LogLevel.Information,
        Message = "DPoP proof rejected at token endpoint: {Reason}.")]
    private partial void LogProofRejected(string reason);
}
