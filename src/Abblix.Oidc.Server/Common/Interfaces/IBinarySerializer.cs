// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Defines the contract for a binary serializer that supports serialization and deserialization of objects
/// to and from binary format.
/// </summary>
public interface IBinarySerializer
{
    /// <summary>
    /// Serializes an object of type <typeparamref name="T"/> to a binary array.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <returns>A binary array representing the serialized object.</returns>
    byte[] Serialize<T>(T obj);

    /// <summary>
    /// Deserializes a binary array to an object of type <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize to.</typeparam>
    /// <param name="bytes">The binary array to deserialize from.</param>
    /// <returns>The deserialized object of type <typeparamref name="T"/>.</returns>
    T? Deserialize<T>(byte[] bytes);
}
