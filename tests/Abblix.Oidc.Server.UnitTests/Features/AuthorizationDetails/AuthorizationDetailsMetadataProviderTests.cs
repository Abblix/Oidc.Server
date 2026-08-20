// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.AuthorizationDetails;

/// <summary>
/// Verifies the discovery surface of RAR - the
/// <c>authorization_details_types_supported</c> metadata field is sourced from the same
/// keyed-DI registry that request-time dispatch uses, and is omitted entirely when zero
/// per-type validators are registered (OIDC discovery convention: absent = unsupported).
/// </summary>
public class AuthorizationDetailsMetadataProviderTests
{
    [Fact]
    public void SupportedTypes_NoValidatorsRegistered_ReturnsNull()
    {
        var sp = BuildProvider();
        var provider = sp.GetRequiredService<IAuthorizationDetailsMetadataProvider>();

        Assert.Null(provider.SupportedTypes);
    }

    [Fact]
    public void SupportedTypes_SingleValidator_ProjectsItsType()
    {
        var sp = BuildProvider(services =>
            services.AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation"));
        var provider = sp.GetRequiredService<IAuthorizationDetailsMetadataProvider>();

        Assert.Equal(["payment_initiation"], provider.SupportedTypes!.ToArray());
    }

    [Fact]
    public void SupportedTypes_MultipleValidators_ProjectsAllInRegistrationOrder()
    {
        var sp = BuildProvider(services => services
            .AddAuthorizationDetailValidator<PaymentValidator>("payment_initiation")
            .AddAuthorizationDetailValidator<AccountValidator>("account_information"));
        var provider = sp.GetRequiredService<IAuthorizationDetailsMetadataProvider>();

        var supported = provider.SupportedTypes!.ToArray();
        Assert.Contains("payment_initiation", supported);
        Assert.Contains("account_information", supported);
        Assert.Equal(2, supported.Length);
    }

    private static ServiceProvider BuildProvider(System.Action<IServiceCollection>? register = null)
    {
        var services = new ServiceCollection();
        services.AddRichAuthorizationRequests();
        register?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private sealed class PaymentValidator : IAuthorizationDetailValidator
    {
        public string Type => "payment_initiation";
        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }

    private sealed class AccountValidator : IAuthorizationDetailValidator
    {
        public string Type => "account_information";
        public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
            AuthorizationDetail detail, ClientInfo client, CancellationToken token)
            => Task.FromResult<Result<AuthorizationDetail, OidcError>>(detail);
    }
}
