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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Storages.Proto.Mappers;
using Google.Protobuf;
using AuthorizationRequest = Abblix.Oidc.Server.Features.Storages.Proto.AuthorizationRequest;
using AuthorizedGrant = Abblix.Oidc.Server.Features.Storages.Proto.AuthorizedGrant;
using AuthSession = Abblix.Oidc.Server.Features.Storages.Proto.AuthSession;
using JsonWebTokenStatus = Abblix.Oidc.Server.Features.Storages.Proto.JsonWebTokenStatus;
using RequestedClaims = Abblix.Oidc.Server.Features.Storages.Proto.RequestedClaims;
using TokenInfo = Abblix.Oidc.Server.Features.Storages.Proto.TokenInfo;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides functionality to serialize and deserialize objects to and from Protocol Buffer binary representations.
/// Implements the <see cref="IBinarySerializer" /> interface using Google.Protobuf for efficient serialization.
/// </summary>
/// <remarks>
/// This serializer supports only specific OIDC storage types that have protobuf definitions and mappers.
/// Attempting to serialize unsupported types will throw InvalidOperationException.
/// </remarks>
public class ProtobufSerializer : IBinarySerializer
{
    /// <summary>
    /// Serializes an object to a binary representation using Protocol Buffers.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <returns>A byte array representing the serialized object.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the type is not supported for protobuf serialization.</exception>
    public byte[] Serialize<T>(T obj)
    {
        // Handle primitive string type directly
        if (obj is string str)
            return System.Text.Encoding.UTF8.GetBytes(str);

        IMessage protoMessage = obj switch
        {
            Tokens.Revocation.JsonWebTokenStatus status => status.ToProto(),
            Endpoints.Token.Interfaces.TokenInfo tokenInfo => tokenInfo.ToProto(),
            Model.RequestedClaims requestedClaims => requestedClaims.ToProto(),
            UserAuthentication.AuthSession authSession => authSession.ToProto(),
            AuthorizationContext authContext => authContext.ToProto(),
            Endpoints.Token.Interfaces.AuthorizedGrant authorizedGrant => authorizedGrant.ToProto(),
            Model.AuthorizationRequest authRequest => authRequest.ToProto(),
            BackChannelAuthenticationRequest bcRequest => bcRequest.ToProto(),
            DeviceAuthorizationRequest deviceRequest => deviceRequest.ToProto(),

            _ => throw new InvalidOperationException(
                $"Type {typeof(T).FullName} is not supported for protobuf serialization. " +
                "Only OIDC storage types with protobuf definitions are supported.")
        };

        return protoMessage.ToByteArray();
    }

    /// <summary>
    /// Deserializes a binary representation to an object using Protocol Buffers.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize into.</typeparam>
    /// <param name="bytes">The binary representation to deserialize from.</param>
    /// <returns>The deserialized object of type <typeparamref name="T" />.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the type is not supported for protobuf deserialization.</exception>
    public T? Deserialize<T>(byte[] bytes)
    {
        if (bytes.Length == 0)
            return default;

        var targetType = typeof(T);

        // Handle primitive string type directly
        if (targetType == typeof(string))
            return (T)(object)System.Text.Encoding.UTF8.GetString(bytes);

        if (targetType == typeof(Tokens.Revocation.JsonWebTokenStatus))
        {
            var proto = JsonWebTokenStatus.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(Endpoints.Token.Interfaces.TokenInfo))
        {
            var proto = TokenInfo.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(Model.RequestedClaims))
        {
            var proto = RequestedClaims.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto()!;
        }

        if (targetType == typeof(UserAuthentication.AuthSession))
        {
            var proto = AuthSession.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(AuthorizationContext))
        {
            var proto = Proto.AuthorizationContext.Parser.ParseFrom(bytes);
            return (T)(object)AuthorizationContextMapper.FromProto(proto);
        }

        if (targetType == typeof(Endpoints.Token.Interfaces.AuthorizedGrant))
        {
            var proto = AuthorizedGrant.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(Model.AuthorizationRequest))
        {
            var proto = AuthorizationRequest.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(BackChannelAuthenticationRequest))
        {
            var proto = Proto.BackChannelAuthenticationRequest.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        if (targetType == typeof(DeviceAuthorizationRequest))
        {
            var proto = Proto.DeviceAuthorizationRequest.Parser.ParseFrom(bytes);
            return (T)(object)proto.FromProto();
        }

        throw new InvalidOperationException(
            $"Type {targetType.FullName} is not supported for protobuf deserialization. " +
            "Only OIDC storage types with protobuf definitions are supported.");
    }
}
