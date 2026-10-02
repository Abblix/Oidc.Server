// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Google.Protobuf;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// How one stored type travels as a Protocol Buffers message: the message it becomes, and the value read back
/// from the bytes of one.
/// </summary>
/// <remarks>
/// Strategy: <see cref="ProtobufSerializer"/> picks one of these by type and knows nothing of any message
/// itself, so a stored type joins by adding one codec rather than an arm to each direction of a switch.
/// </remarks>
/// <param name="valueType">The stored type this codec serves.</param>
/// <param name="toMessage">Builds the message a value is stored as.</param>
/// <param name="fromBytes">Reads the value back from the bytes of its message.</param>
internal sealed class ProtobufCodec(Type valueType, Func<object, IMessage> toMessage, Func<byte[], object?> fromBytes)
{
    /// <summary>
    /// The stored type this codec serves.
    /// </summary>
    public Type ValueType => valueType;

    /// <summary>
    /// The message <paramref name="value"/> is stored as.
    /// </summary>
    public IMessage ToMessage(object value) => toMessage(value);

    /// <summary>
    /// The value the message in <paramref name="bytes"/> stands for.
    /// </summary>
    public object? FromBytes(byte[] bytes) => fromBytes(bytes);

    /// <summary>
    /// A domain type carried by a message its mapper translates to and from.
    /// </summary>
    public static ProtobufCodec Mapped<TValue, TMessage>(
        MessageParser<TMessage> parser,
        Func<TValue, TMessage> toProto,
        Func<TMessage, TValue> fromProto)
        where TMessage : IMessage<TMessage>
        => new(typeof(TValue), value => toProto((TValue)value), bytes => fromProto(parser.ParseFrom(bytes)));

    /// <summary>
    /// A message stored as it is, with no domain type mapped onto it.
    /// </summary>
    public static ProtobufCodec Stored<TMessage>(MessageParser<TMessage> parser)
        where TMessage : IMessage<TMessage>
        => Mapped<TMessage, TMessage>(parser, message => message, message => message);
}
