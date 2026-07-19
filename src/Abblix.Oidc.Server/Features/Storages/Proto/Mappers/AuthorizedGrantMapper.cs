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
