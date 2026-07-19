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

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between JsonWebTokenStatus C# enum and protobuf message.
/// </summary>
internal static class JsonWebTokenStatusMapper
{
    /// <summary>
    /// Converts a C# JsonWebTokenStatus enum to a protobuf message.
    /// </summary>
    public static JsonWebTokenStatus ToProto(this Tokens.Revocation.JsonWebTokenStatus source)
    {
        var enumValue = source switch
        {
            Tokens.Revocation.JsonWebTokenStatus.Unknown => JsonWebTokenStatusEnum.Unknown,
            Tokens.Revocation.JsonWebTokenStatus.Used => JsonWebTokenStatusEnum.Used,
            Tokens.Revocation.JsonWebTokenStatus.Revoked => JsonWebTokenStatusEnum.Revoked,
            _ => JsonWebTokenStatusEnum.Unknown,
        };

        return new JsonWebTokenStatus { Status = enumValue };
    }

    /// <summary>
    /// Converts a protobuf JsonWebTokenStatus message to a C# enum.
    /// </summary>
    public static Tokens.Revocation.JsonWebTokenStatus FromProto(this JsonWebTokenStatus source)
    {
        return source.Status switch
        {
            JsonWebTokenStatusEnum.Unknown => Tokens.Revocation.JsonWebTokenStatus.Unknown,
            JsonWebTokenStatusEnum.Used => Tokens.Revocation.JsonWebTokenStatus.Used,
            JsonWebTokenStatusEnum.Revoked => Tokens.Revocation.JsonWebTokenStatus.Revoked,
            _ => Tokens.Revocation.JsonWebTokenStatus.Unknown,
        };
    }
}
