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
    /// How many documentation files sit beside the tests - which is what the gate reads.
    /// </summary>
    /// <remarks>
    /// A count of the OUTPUT, not of the reference list, and the two do not follow from one another:
    /// measured, a reference dropped from the project file still arrives when another referenced project
    /// pulls it in, so half the list can be removed with the output unchanged - and unharmed, since the
    /// documentation the gate reads is still there. What the earlier version of this sentence said, that
    /// the reference count is THEREFORE the file count, is the step that does not hold.
    /// <para>
    /// Asserted for equality rather than as a floor, and bumped by hand when a library is added, which
    /// is the same deliberate moment <see cref="Unenrolled"/> is built around. A floor of seven let the nine
    /// sample-free references go at once with every row green, taking seven of the sixteen documents
    /// with them - two of the nine survive, arriving through libraries that cannot be dropped. And it
    /// would NOT have surfaced later: a sample added to a library whose documentation has left the
    /// output is invisible to the count, measured, so the gate simply never sees it. That is why the
    /// equality is the guard rather than a promise about some future day.
    /// </para>
    /// <para>
    /// Sixteen of the eighteen projects under <c>src/</c>. The two source generators are NOT referenced,
    /// and that is a hole rather than a tidiness: they emit documentation and ship inside the Mvc and
    /// MinimalApi packages, so a sample written into either is invisible here. Referencing them was
    /// tried and refused by the runtime - a generator assembly needs the compiler's own assemblies to
    /// enumerate its types, which are not copied to a test output, so the stub row throws
    /// <c>ReflectionTypeLoadException</c>. Carrying just their documentation would mean copying an XML
    /// file out of another project's <c>bin</c> by path, which pins a framework name and a build order.
    /// Named here rather than left to be discovered, because a cap nobody wrote down reads afterwards
    /// as coverage.
    /// </para>
    /// </remarks>
    public const int Libraries = 16;

    /// <summary>
    /// How many projects under <c>src/</c> this one names in its own project file.
    /// </summary>
    /// <remarks>
    /// The same number as <see cref="Libraries"/> today and a different QUANTITY, which is why it has
    /// its own name: one counts what the project asks for, the other what the build put beside the
    /// tests, and the previous round was spent discovering that neither implies the other.
    /// <para>
    /// Asserted because the list that carries it can arrive EMPTY without anything failing. It is
    /// written by MSBuild into an assembly attribute, and three edits leave the READER with nothing:
    /// a renamed key (the attribute is still there, under a name the reader does not ask for), a
    /// deleted item group (no attribute at all), and the group placed above the references it reads
    /// (the attribute present with an empty value). Only the third is literally empty, which an
    /// earlier version of this sentence claimed of all three. Measured: renaming the key alone left
    /// all four rows green. The version before it threw when its input was missing, which is a worse
    /// design with a better failure.
    /// </para>
    /// </remarks>
    public const int References = 16;

    /// <summary>
    /// How many distinct code samples the compiler recorded that nothing here compiles.
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
    public const int Unenrolled = 12;
}
