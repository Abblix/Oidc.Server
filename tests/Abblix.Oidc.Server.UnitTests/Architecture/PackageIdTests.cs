// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    /// <summary>
    /// Whether the project can be packed: one that never sets <c>IsPackable</c> to anything but <c>false</c> is not.
    /// </summary>
    private static bool IsPackable(XDocument project)
        => project.Descendants("IsPackable").Any(element => element.Value != "false");

    [Fact]
    public void EveryPackableProject_DeclaresThePackageIdItsNameYields()
    {
        var projects = Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot(), "src"), "*.csproj", SearchOption.AllDirectories)
            .Select(path => (Name: Path.GetFileNameWithoutExtension(path), Document: XDocument.Load(path)))
            .ToList();
        Assert.Contains(projects, project => project.Name == "Abblix.Oidc.Server" && IsPackable(project.Document));

        var problems = projects
            .Select(project => (project.Name, Declared: project.Document.Descendants("PackageId").SingleOrDefault()?.Value,
                Packable: IsPackable(project.Document)))
            .Where(project => project.Declared is not null || project.Packable)
            .Where(project => project.Declared != ExpectedPackageId(project.Name))
            .Select(project => $"{project.Name}: declares '{project.Declared}', expected '{ExpectedPackageId(project.Name)}'")
            .ToList();

        Assert.Empty(problems);
    }
}
