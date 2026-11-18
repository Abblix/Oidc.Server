// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    /// <summary>
    /// The response carries how the session it was issued under is kept, which the session management cookie written
    /// beside it is given.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_CarriesHowTheSessionIsKept()
    {
        var request = CreateRequest();
        var persistence = SessionPersistence.Until(DateTimeOffset.FromUnixTimeSeconds(1_900_000_000));
        var session = CreateAuthSession() with { Persistence = persistence };
        SetupSuccessfulAuthCodeFlow(request, session, CreateConsents());

        var response = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.Equal(persistence, Assert.IsType<SuccessfullyAuthenticated>(response).SessionPersistence);
    }
}
