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

using Abblix.Utils.Json;
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
            AuthenticationTime = Timestamp.FromDateTimeOffset(source.AuthenticationTime),
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

        proto.AdditionalClaims = source.AdditionalClaims.ToProtoStruct();

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
            AffectedClientIds = source.AffectedClientIds.ToList(),
            AuthenticationMethodReferences = source.AuthenticationMethodReferences.Count > 0
                ? source.AuthenticationMethodReferences.ToList()
                : null,
            Email = ProtoMapper.GetString(source.Email, source.HasEmail),
            EmailVerified = source.HasEmailVerified ? source.EmailVerified : null,
            AdditionalClaims = source.AdditionalClaims.ToJsonObject(),
        };
    }
}
