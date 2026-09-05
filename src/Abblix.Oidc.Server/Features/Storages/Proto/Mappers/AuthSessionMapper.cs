// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils.Collections;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between AuthSession C# record and protobuf message.
/// </summary>
internal static class AuthSessionMapper
{
    /// <summary>
    /// Converts a C# AuthSession record to a protobuf message.
    /// </summary>
    public static AuthSession ToProto(this Features.UserAuthentication.AuthSession source)
    {
        var proto = new AuthSession
        {
            Subject = source.Subject,
            SessionId = source.SessionId,
            AuthenticationTime = source.AuthenticationTime.ToTimestamp(),
            IdentityProvider = source.IdentityProvider ?? string.Empty,
        };

        if (source.AuthContextClassRef != null)
            proto.AuthContextClassRef = source.AuthContextClassRef;

        proto.AffectedClientIds.AddIfNotNull(source.AffectedClientIds);
        proto.AuthenticationMethodReferences.AddIfNotNull(source.AuthenticationMethodReferences);

        if (source.Email != null)
            proto.Email = source.Email;

        if (source.EmailVerified.HasValue)
            proto.EmailVerified = source.EmailVerified.Value;

        proto.AdditionalClaims = source.AdditionalClaims.ToStruct();

        return proto;
    }

    /// <summary>
    /// Converts a protobuf AuthSession message to a C# record.
    /// </summary>
    public static Features.UserAuthentication.AuthSession FromProto(this AuthSession source)
    {
        return new Features.UserAuthentication.AuthSession(
            source.Subject,
            source.SessionId,
            source.AuthenticationTime.ToDateTimeOffset(),
            source.IdentityProvider)
        {
            AuthContextClassRef = ProtoMapper.GetString(source.AuthContextClassRef, source.HasAuthContextClassRef),
            AffectedClientIds = new ConcurrentSet<string>(source.AffectedClientIds),
            AuthenticationMethodReferences = source.AuthenticationMethodReferences.Count > 0
                ? source.AuthenticationMethodReferences.ToList()
                : null,
            Email = ProtoMapper.GetString(source.Email, source.HasEmail),
            EmailVerified = source.HasEmailVerified ? source.EmailVerified : null,
            AdditionalClaims = source.AdditionalClaims.ToJsonObject(),
        };
    }
}
