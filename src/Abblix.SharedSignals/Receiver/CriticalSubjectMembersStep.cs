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

using System.Text.Json;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Subjects;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Enforces the receiver half of subject processing (SSF 1.0 Section 3.6): an event whose
/// subject carries a critical member this receiver cannot interpret is discarded, never
/// processed with the member silently dropped - acting on a subject while blind to a member the
/// transmitter declared essential could act on the wrong principal.
/// </summary>
/// <remarks>
/// "Unable to process" is structural here: a complex-subject member the subject vocabulary
/// interprets lands in a typed property, and one it cannot interpret survives only as raw JSON
/// in <see cref="ComplexSubject.AdditionalMembers"/> - which is exactly the set this step
/// checks the critical names against. A "sub_id" that does not parse at all is rejected on the
/// same reasoning: a receiver that cannot name the subject cannot process any member of it.
/// An absent "sub_id" passes - whether the claim is required at all belongs to the event's own
/// rules, not to this step.
/// </remarks>
public sealed class CriticalSubjectMembersStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.SignatureVerified);

        if (context.Options is not SsfValidationOptions options)
        {
            throw new InvalidOperationException(
                $"{nameof(CriticalSubjectMembersStep)} requires {nameof(SsfValidationOptions)}: the "
                + "critical member names and the subject vocabulary live there.");
        }

        SubjectIdentifier? subjectId;
        try
        {
            subjectId = context.Token!.GetSubjectId(options.SubjectSerializerOptions);
        }
        catch (JsonException exception)
        {
            return ValueTask.FromResult<SecurityEventTokenValidationError?>(new(
                SecurityEventTokenErrorCode.Custom,
                "The 'sub_id' claim is not a Subject Identifier this receiver understands: "
                + $"{exception.Message}"));
        }

        if (subjectId is ComplexSubject { AdditionalMembers.Count: > 0 } complex)
        {
            var unprocessable = options.CriticalSubjectMembers
                .Where(complex.AdditionalMembers.ContainsKey)
                .ToArray();

            if (unprocessable.Length > 0)
            {
                return ValueTask.FromResult<SecurityEventTokenValidationError?>(new(
                    SecurityEventTokenErrorCode.Custom,
                    $"The subject carries critical member(s) '{string.Join("', '", unprocessable)}' this "
                    + "receiver cannot interpret; such an event must be discarded "
                    + "(SSF 1.0 Section 3.6)."));
            }
        }

        return ValueTask.FromResult<SecurityEventTokenValidationError?>(null);
    }
}
