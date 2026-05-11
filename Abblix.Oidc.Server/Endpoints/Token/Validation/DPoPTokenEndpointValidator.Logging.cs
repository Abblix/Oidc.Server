// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
