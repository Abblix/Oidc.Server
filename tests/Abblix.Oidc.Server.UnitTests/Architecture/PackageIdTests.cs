// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// Every package published from this repository carries the id its project name yields.
/// </summary>
/// <remarks>
/// Project, assembly and namespace spell an acronym as a word (<c>Abblix.Oidc.Server.Mvc</c>), while the published
/// id spells it the way people search for it (<c>Abblix.OIDC.Server.MVC</c>), so every project overrides its
/// <c>PackageId</c> by hand. Nothing builds or packs differently when one spelling is missed, and an id cannot be
/// renamed once a version is published under it, so the mismatch is caught here, before the first push.
/// <para>
/// Whether a project packs and under which id is asked of MSBuild rather than read from the project file: the SDK
/// packs a class library that never mentions <c>IsPackable</c>, and a property can come from a condition or an
/// imported file, none of which the text of the project shows.
/// </para>
/// </remarks>
public class PackageIdTests
{
    /// <summary>
    /// How each name segment that is an acronym is spelled in a package id. A project whose name holds an acronym
    /// missing here fails until its spelling is added.
    /// </summary>
    private static readonly Dictionary<string, string> AcronymSpellings = new(StringComparer.Ordinal)
    {
        ["Oidc"] = "OIDC",
        ["Jwt"] = "JWT",
        ["Mvc"] = "MVC",
        ["MinimalApi"] = "MinimalAPI",
    };

    private static string ExpectedPackageId(string projectName)
        => string.Join('.', projectName.Split('.').Select(segment =>
            AcronymSpellings.TryGetValue(segment, out var spelling) ? spelling : segment));

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }

    private sealed record PackageProperties(string Project, bool IsPackable, string PackageId);

    private static async Task<PackageProperties> EvaluateAsync(string root, string projectPath)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            ArgumentList = { "msbuild", projectPath, "-getProperty:IsPackable", "-getProperty:PackageId" },
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(start);
        Assert.NotNull(process);
        var output = await process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.True(process.ExitCode == 0, $"MSBuild could not evaluate {projectPath}: {output}");

        var properties = JsonDocument.Parse(output).RootElement.GetProperty("Properties");
        return new PackageProperties(
            Path.GetFileNameWithoutExtension(projectPath),
            properties.GetProperty("IsPackable").GetString() == "true",
            properties.GetProperty("PackageId").GetString() ?? string.Empty);
    }

    [Fact]
    public async Task EveryPackableProject_DeclaresThePackageIdItsNameYields()
    {
        var root = RepositoryRoot();
        var projectPaths = XDocument.Load(Path.Combine(root, "Abblix.Oidc.slnx"))
            .Descendants("Project")
            .Select(project => (string?)project.Attribute("Path"))
            .OfType<string>()
            .ToList();

        var projects = await Task.WhenAll(projectPaths.Select(path => EvaluateAsync(root, path)));
        Assert.Contains(projects, project => project is { Project: "Abblix.Oidc.Server", IsPackable: true });

        var problems = projects
            .Where(project => project.IsPackable && project.PackageId != ExpectedPackageId(project.Project))
            .Select(project =>
                $"{project.Project}: packs as '{project.PackageId}', expected '{ExpectedPackageId(project.Project)}'")
            .ToList();

        Assert.Empty(problems);
    }
}
