// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.DocSamples;

/// <summary>
/// Which doc-comment samples the compiler checks, and how many it does not yet.
/// </summary>
/// <remarks>
/// Enrolment is per sample rather than automatic, because a sample has to be made compilable before it
/// can be compiled: a three-line fragment needs the ambient names it calls into, and a whole class needs
/// whatever the integrator's own half invents. That is work per sample, so this list grows deliberately.
/// <para>
/// What keeps the remainder from being forgotten is <see cref="Unenrolled"/>: the count of blocks nobody
/// has enrolled is asserted, so adding a sample to the library forces a decision - enrol it, or move the
/// number and say why in the commit. A gate whose coverage can silently shrink to nothing is the shape
/// this whole file exists to avoid.
/// </para>
/// </remarks>
public static class Enrolment
{
    /// <summary>
    /// The samples whose text is compiled, each with a copy under <c>Samples/</c>, named by the
    /// documentation identifier the compiler writes for the member they document.
    /// </summary>
    public static IReadOnlyList<DocSample> Compiled { get; } =
    [
        new("M:Abblix.Jwt.Vault.ServiceCollectionExtensions.AddVaultCustodian("
            + "Microsoft.Extensions.DependencyInjection.IServiceCollection,"
            + "System.Action{Abblix.Jwt.Vault.VaultTransitOptions})", 0, "VaultCustodian.cs"),

        new("M:Abblix.Jwt.Azure.ServiceCollectionExtensions.AddAzureCustodian("
            + "Microsoft.Extensions.DependencyInjection.IServiceCollection,"
            + "System.Action{Abblix.Jwt.Azure.AzureKeyVaultOptions})", 0, "AzureCustodian.cs"),

        new("P:Abblix.Oidc.Server.Features.UserAuthentication.AuthSession.AdditionalClaims", 0,
            "AdditionalClaims.cs"),

        new("M:Abblix.Oidc.Server.Features.BackChannelAuthentication.UserDeviceAuthenticationHandlerStub"
            + ".InitiateAuthenticationAsync("
            + "Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces"
            + ".ValidBackChannelAuthenticationRequest)", 0, "BackChannelHandler.cs"),
    ];

    /// <summary>
    /// How many code blocks the compiler recorded that nothing here compiles.
    /// </summary>
    /// <remarks>
    /// A number rather than a list, because the list is what the enrolment above is for. It is meant to
    /// FALL: every sample enrolled takes one off it, and a sample added to the library puts one on, which
    /// is the moment somebody has to decide.
    /// <para>
    /// The two CIBA samples are the ones a rename actually rotted, and they are the next to enrol. They
    /// were deferred while their text was in flight on another branch; that branch has since landed, so
    /// the reason is spent and what remains is the work of making each sample compilable - the ambient
    /// names a fragment calls into, and a stub for whatever the integrator's own half invents.
    /// </para>
    /// </remarks>
    public const int Unenrolled = 14;
}
