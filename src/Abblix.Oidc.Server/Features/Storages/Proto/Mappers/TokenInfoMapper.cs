// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between TokenInfo C# record and protobuf message.
/// </summary>
internal static class TokenInfoMapper
{
    /// <summary>
    /// Converts a C# TokenInfo record to a protobuf message.
    /// </summary>
    public static TokenInfo ToProto(this Endpoints.Token.Interfaces.TokenInfo source)
    {
        return new TokenInfo
        {
            JwtId = source.JwtId,
            ExpiresAt = source.ExpiresAt.ToTimestamp(),
        };
    }

    /// <summary>
    /// Converts a protobuf TokenInfo message to a C# record.
    /// </summary>
    public static Endpoints.Token.Interfaces.TokenInfo FromProto(this TokenInfo source)
    {
        return new Endpoints.Token.Interfaces.TokenInfo(
            source.JwtId,
            source.ExpiresAt.ToDateTimeOffset());
    }
}
