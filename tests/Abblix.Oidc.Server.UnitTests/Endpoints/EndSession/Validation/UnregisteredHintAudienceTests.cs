// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// An end-session request carrying no client_id takes its client from the hint's audience, and a client
/// nobody registered is refused by the end-session pipeline as the library composes it.
/// </summary>
/// <remarks>
/// Asked of the registered pipeline rather than of one validator, because the refusal depends on ORDER: the
/// client check reads the client the hint validator resolved, so with the two swapped it would find no
/// client at all and let the request through.
/// </remarks>
public class UnregisteredHintAudienceTests
{
    private const string IdTokenHint = "id_token_hint_value";
    private const string Unregistered = "unregistered_client";

    [Fact]
    public async Task AHintNamingAnUnregisteredClient_IsRefusedAsAnUnauthorizedClient()
    {
        var idToken = new JsonWebToken();
        idToken.Payload.Audiences = [Unregistered];

        var hintParser = new Mock<IIdTokenHintParser>(MockBehavior.Strict);
        hintParser
            .Setup(p => p.ParseAsync(IdTokenHint))
            .ReturnsAsync((Result<JsonWebToken, string>)idToken);

        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(Unregistered))
            .ReturnsAsync((ClientInfo?)null);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(hintParser.Object);
        services.AddSingleton(clientInfoProvider.Object);
        // Loose, so a request the client check lets through reaches the end of the pipeline and fails on the
        // missing error rather than on a mock.
        services.AddSingleton(Mock.Of<IAuthSessionService>());
        services.AddSingleton(Mock.Of<ISubjectTypeConverter>());
        services.AddSingleton(Mock.Of<ILogoutConfirmationStore>());
        services.AddSingleton(SingleIssuer.Settings);
        services.AddEndSessionContextValidators();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var validator = scope.ServiceProvider.GetRequiredService<IEndSessionContextValidator>();

        var context = new EndSessionValidationContext(new EndSessionRequest { IdTokenHint = IdTokenHint });
        var error = await validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Equal(Unregistered, context.ClientId);
        clientInfoProvider.Verify(p => p.TryFindClientAsync(Unregistered), Times.Once);
    }
}
