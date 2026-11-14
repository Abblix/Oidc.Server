// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// How one stored type travels as bytes in the Protocol Buffers serializer: the bytes a value is written as, and
/// the value read back from them.
/// </summary>
/// <remarks>
/// Strategy: <see cref="ProtobufSerializer"/> picks one of these by type and knows nothing of any message itself,
/// so a stored type joins by adding one codec rather than an arm to each direction of a switch.
/// </remarks>
internal interface IProtobufCodec
{
    /// <summary>
    /// The stored type this codec serves.
    /// </summary>
    Type ValueType { get; }

    /// <summary>
    /// The bytes <paramref name="value"/> is stored as.
    /// </summary>
    byte[] ToBytes(object value);

    /// <summary>
    /// The value <paramref name="bytes"/> stand for.
    /// </summary>
    object? FromBytes(byte[] bytes);
}
