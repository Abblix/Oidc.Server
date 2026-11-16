// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The suite's configuration files for the plans run with static clients, which the suite reads a FAPI plan's clients,
/// keys and certificates from.
/// </summary>
public static class PlanConfigurationFiles
{
    /// <summary>Writes one file per configuration into <paramref name="directory"/>, named by its alias.</summary>
    /// <param name="directory">The directory the run script names.</param>
    /// <param name="configurations">The configurations by their aliases.</param>
    public static async Task WriteAsync(
        string directory,
        IEnumerable<KeyValuePair<string, JsonObject>> configurations)
    {
        Directory.CreateDirectory(directory);
        foreach (var (alias, configuration) in configurations)
        {
            await File.WriteAllTextAsync(
                Path.Combine(directory, alias + ".json"),
                configuration.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}
