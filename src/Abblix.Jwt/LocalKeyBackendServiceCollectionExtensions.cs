// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Registers the in-process backends of the signing and key-recovery seams.
/// </summary>
internal static class LocalKeyBackendServiceCollectionExtensions
{
    /// <summary>
    /// Places <see cref="LocalKeySigner"/> and <see cref="LocalKeyDecryptor"/> in their families, where each owns
    /// the keys that carry their private material.
    /// </summary>
    internal static IServiceCollection AddLocalKeyBackends(this IServiceCollection services)
    {
        // The signing seam behind IJsonWebTokenSigner is a composition of key-owning backends (IDataSigner):
        // the in-process LocalKeySigner owns private-bearing keys and is the sole backend by default. A host
        // adds HSM/KMS/vault signing by wiring an IKeyCustodian, which adds an external backend and composes
        // the family; the composite then routes each key to the backend that owns it and fails closed when
        // none does.
        //
        // Placed through the family cursor rather than TryAddEnumerable, because this method is called more
        // than once by design - the OIDC registration performs it, and so does the security-event one - so a
        // host may well have composed the family in between. TryAddEnumerable dedupes against plain
        // descriptors and a composed family is keyed, so it would leave a second copy beside the composite
        // that silently wins the resolve.
        services.Decompose<IDataSigner>().AddLast(ServiceDescriptor.Singleton<IDataSigner, LocalKeySigner>());

        // The key-recovery seam behind IJsonWebTokenEncryptor mirrors the signing seam in every respect: the
        // in-process LocalKeyDecryptor owns keys that carry their secret half and is the sole backend by default.
        // Encryption (wrapping the CEK) uses the recipient's public half or a local secret and never routes here,
        // so there is no encryptor seam.
        services.Decompose<IContentKeyDecryptor>()
            .AddLast(ServiceDescriptor.Singleton<IContentKeyDecryptor, LocalKeyDecryptor>());

        return services;
    }
}
