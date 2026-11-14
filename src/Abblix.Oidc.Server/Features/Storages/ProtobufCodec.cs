// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// The codec of one stored type, named in its own type so the build can tell which types have one.
/// </summary>
/// <remarks>
/// ABX1009 refuses a call to the entity storage whose type no codec of this kind serves, which keeps every
/// stored type on a schema of fixed field numbers rather than the JSON the serializer falls back to.
/// </remarks>
/// <typeparam name="TValue">The stored type this codec serves.</typeparam>
/// <param name="toBytes">Builds the bytes a value is stored as.</param>
/// <param name="fromBytes">Reads the value back from its bytes.</param>
internal sealed class ProtobufCodec<TValue>(Func<TValue, byte[]> toBytes, Func<byte[], TValue> fromBytes)
    : IProtobufCodec
{
    /// <inheritdoc />
    public Type ValueType => typeof(TValue);

    /// <inheritdoc />
    public byte[] ToBytes(object value) => toBytes((TValue)value);

    /// <inheritdoc />
    public object? FromBytes(byte[] bytes) => fromBytes(bytes);
}
