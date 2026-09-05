// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
