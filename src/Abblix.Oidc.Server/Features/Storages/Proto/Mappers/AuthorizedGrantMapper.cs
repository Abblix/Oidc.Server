// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between AuthorizedGrant C# record and protobuf message.
/// </summary>
internal static class AuthorizedGrantMapper
{
    /// <summary>
    /// Converts a C# AuthorizedGrant record to a protobuf message.
    /// </summary>
    public static AuthorizedGrant ToProto(this Endpoints.Token.Interfaces.AuthorizedGrant source)
    {
        var proto = new AuthorizedGrant
        {
            AuthSession = source.AuthSession.ToProto(),
            Context = source.Context.ToProto(),
        };

        proto.IssuedTokens.AddIfNotNull(source.IssuedTokens, TokenInfoMapper.ToProto);

        return proto;
    }

    /// <summary>
    /// Converts a protobuf AuthorizedGrant message to a C# record.
    /// </summary>
    public static Endpoints.Token.Interfaces.AuthorizedGrant FromProto(this AuthorizedGrant source)
    {
        return new Endpoints.Token.Interfaces.AuthorizedGrant(
            source.AuthSession.FromProto(),
            AuthorizationContextMapper.FromProto(source.Context))
        {
            IssuedTokens = source.IssuedTokens.GetArray(TokenInfoMapper.FromProto),
        };
    }
}
