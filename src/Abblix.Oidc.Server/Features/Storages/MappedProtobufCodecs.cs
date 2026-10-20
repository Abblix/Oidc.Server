// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// The codecs of the domain types stored as Protocol Buffers messages, each carried by the message its mapper
/// translates to and from.
/// </summary>
internal static class MappedProtobufCodecs
{
    /// <summary>
    /// One codec per mapped domain type.
    /// </summary>
    [CodecRegistry]
    public static readonly IProtobufCodec[] All =
    [
        ProtobufCodecs.Mapped(
            Proto.JsonWebTokenStatus.Parser,
            (Tokens.Revocation.JsonWebTokenStatus status) => status.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.TokenInfo.Parser,
            (Endpoints.Token.Interfaces.TokenInfo tokenInfo) => tokenInfo.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.RequestedClaims.Parser,
            (Model.RequestedClaims requestedClaims) => requestedClaims.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.AuthSession.Parser,
            (UserAuthentication.AuthSession authSession) => authSession.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.AuthorizationContext.Parser,
            (AuthorizationContext authContext) => authContext.ToProto(),
            AuthorizationContextMapper.FromProto),
        ProtobufCodecs.Mapped(
            Proto.AuthorizedGrant.Parser,
            (Endpoints.Token.Interfaces.AuthorizedGrant authorizedGrant) => authorizedGrant.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.AuthorizationRequest.Parser,
            (Model.AuthorizationRequest authRequest) => authRequest.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.BackChannelAuthenticationRequest.Parser,
            (BackChannelAuthenticationRequest bcRequest) => bcRequest.ToProto(),
            proto => proto.FromProto()),
        ProtobufCodecs.Mapped(
            Proto.DeviceAuthorizationRequest.Parser,
            (DeviceAuthorizationRequest deviceRequest) => deviceRequest.ToProto(),
            proto => proto.FromProto()),
    ];
}
