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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Default <see cref="ISubjectClaimsService"/>: derives the client-facing <c>sub</c> via
/// <see cref="ISubjectTypeConverter"/> and, when it is a pairwise pseudonym, protects the real subject into
/// <c>psub</c> via <see cref="ISubjectProtector"/>.
/// </summary>
/// <param name="subjectTypeConverter">Computes the client's subject type value (public passthrough or pairwise).</param>
/// <param name="subjectProtector">Reversibly protects/recovers the real subject.</param>
public class SubjectClaimsService(
    ISubjectTypeConverter subjectTypeConverter,
    ISubjectProtector subjectProtector) : ISubjectClaimsService
{
    /// <inheritdoc />
    public void WriteSubject(JsonWebTokenPayload payload, string realSubject, ClientInfo clientInfo)
    {
        var subject = subjectTypeConverter.Convert(realSubject, clientInfo);
        payload.Subject = subject;

        // Only a pairwise client changes the subject; when it does, the real subject can no longer be read back
        // from sub (the pairwise HMAC is one-way), so carry it protected in psub. A public client leaves sub as
        // the real subject and needs no psub.
        payload.ProtectedSubject = subject != realSubject
            ? subjectProtector.Protect(realSubject)
            : null;
    }

    /// <inheritdoc />
    public string RecoverSubject(JsonWebTokenPayload payload)
        => payload.ProtectedSubject is { } handle
            ? subjectProtector.Unprotect(handle)
            : payload.Subject.NotNull(nameof(payload.Subject));
}
