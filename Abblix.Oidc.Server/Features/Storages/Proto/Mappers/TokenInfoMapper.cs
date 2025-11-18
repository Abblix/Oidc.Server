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
            ExpiresAt = Timestamp.FromDateTimeOffset(source.ExpiresAt),
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
