// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Registered by the MVC adapter only to say it is registered: the other adapter recognizes it by the assembly
/// that declares it, and refuses to be added beside it.
/// </summary>
[SuppressMessage("Major Code Smell", "S2094:Classes should not be empty",
    Justification = "The empty body is the point: the type is the mark the other adapter finds, and it carries no data.")]
internal sealed class MvcAdapterMarker;
