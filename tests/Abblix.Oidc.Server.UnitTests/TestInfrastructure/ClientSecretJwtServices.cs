// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The services a <see cref="Abblix.Oidc.Server.Features.ClientAuthentication.ClientSecretJwtAuthenticator"/> resolves per request: the
/// client JWT validator it validates the assertion through, over the JWT validator a test gives it.
/// </summary>
public static class ClientSecretJwtServices
{
    /// <summary>
    /// <paramref name="services"/>, or none, with a <see cref="ClientJwtValidator"/> over <paramref name="validator"/>
    /// reading the time from <paramref name="clock"/> and decrypting secrets with <paramref name="encryptor"/>.
    /// </summary>
    /// <param name="validator">The JWT validator the assertion is validated with.</param>
    /// <param name="clock">The time a secret's expiry and the token's timestamps are judged against.</param>
    /// <param name="services">The services the test registers itself, or null.</param>
    /// <param name="encryptor">Decrypts a secret kept encrypted, or null for one decrypting nothing.</param>
    public static IServiceProvider With(
        ProfiledJwtValidator validator,
        TimeProvider clock,
        IServiceCollection? services = null,
        IClientSecretEncryptor? encryptor = null)
    {
        var clientJwtValidator = new ClientJwtValidator(
            NullLogger<ClientJwtValidator>.Instance,
            Mock.Of<IRequestInfoProvider>(),
            validator,
            Mock.Of<IClientKeysProvider>(),
            Mock.Of<IAuthServiceKeysProvider>(),
            clock,
            encryptor ?? Mock.Of<IClientSecretEncryptor>());

        return (services ?? new ServiceCollection())
            .AddSingleton<IClientJwtValidator>(clientJwtValidator)
            .BuildServiceProvider(validateScopes: true);
    }
}
