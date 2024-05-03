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
