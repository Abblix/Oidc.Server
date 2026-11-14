// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Google.Protobuf;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// The kinds of codec a stored type can have.
/// </summary>
internal static class ProtobufCodecs
{
    /// <summary>
    /// A domain type carried by a message its mapper translates to and from.
    /// </summary>
    public static ProtobufCodec<TValue> Mapped<TValue, TMessage>(
        MessageParser<TMessage> parser,
        Func<TValue, TMessage> toProto,
        Func<TMessage, TValue> fromProto)
        where TMessage : IMessage<TMessage>
        => new(value => toProto(value).ToByteArray(), bytes => fromProto(parser.ParseFrom(bytes)));

    /// <summary>
    /// A message stored as it is, with no domain type mapped onto it.
    /// </summary>
    public static ProtobufCodec<TMessage> Stored<TMessage>(MessageParser<TMessage> parser)
        where TMessage : IMessage<TMessage>
        => Mapped<TMessage, TMessage>(parser, message => message, message => message);

    /// <summary>
    /// A string stored as its UTF-8 bytes, which is what a string reads back from whatever wrote it before.
    /// </summary>
    public static ProtobufCodec<string> Text()
        => new(Encoding.UTF8.GetBytes, Encoding.UTF8.GetString);
}
