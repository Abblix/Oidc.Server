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
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// A value handed to a replaceable implementation, and then read back by the caller that handed it over.
/// </summary>
/// <remarks>
/// Everything reached through an interface here is a seam a host can occupy, and narrowing by editing what
/// you were given is how narrowing is written throughout this repository. So a caller that hands an object
/// to such a call and afterwards measures anything against that same object is asking a question whose
/// answer the callee has already had the chance to change - and the failure is silent: the value still
/// looks like a request, it just no longer says what was asked for.
/// <para>
/// The shape is an ORDER of statements inside one method, which is why this walks the syntax rather than
/// the text. What it does NOT see is listed on <see cref="TheShapesThisTestCannotSee"/>.
/// </para>
/// </remarks>
public class ValueHandedToAHostSeamTests
{
    /// <summary>
    /// A member whose value can be edited without replacing it, so handing it over lends it out.
    /// </summary>
    private static bool IsMutableInPlace(TypeSyntax? type)
    {
        if (type is null) return false;

        var text = type.ToString().TrimEnd('?');
        if (text.EndsWith("[]", StringComparison.Ordinal)) return true;

        var generic = text.Split('<')[0];
        return generic is "JsonArray" or "JsonObject" or "JsonNode"
            or "List" or "Dictionary" or "HashSet" or "SortedSet" or "SortedDictionary"
            or "ICollection" or "IList" or "IDictionary" or "ISet";
    }

    private static string Normalized(SyntaxNode node)
        => string.Concat(node.ToString().Where(c => !char.IsWhiteSpace(c)));

    /// <summary>
    /// The marker a site uses to say the read-back is the point, and why.
    /// </summary>
    /// <remarks>
    /// Touching a value after handing it to a store is sometimes the whole intent - echoing what was
    /// registered, including the defaults the server assigned, or writing the change that gets
    /// persisted. The walker cannot tell that from a yardstick somebody moved, so the site says which
    /// it is, at the site, with a reason.
    /// <para>
    /// The marker NAMES the member it excuses, so it stays a silence about one thing rather than about
    /// the call: a read of something else added later is reported as if the marker were not there. And
    /// a marker describing nothing fails, so one left behind by a later edit is not a silence anybody
    /// keeps.
    /// </para>
    /// </remarks>
    private const string Declared = "// lent deliberately";

    private static bool IsDeclared(SyntaxNode call, string member)
    {
        for (var node = call; node is not null; node = node.Parent)
        {
            if (node is not StatementSyntax) continue;

            var leading = node.GetLeadingTrivia().ToString();
            return leading.Contains($"{Declared} {member}:", StringComparison.Ordinal);
        }

        return false;
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }

    private static IReadOnlyList<(string Path, CompilationUnitSyntax Root)> LibrarySources()
    {
        var source = Path.Combine(RepositoryRoot(), "src");
        var files = Directory
            .EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                           && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .ToArray();

        // A file that cannot be read hides every occurrence in it from every walker, and reads exactly
        // like a clean one - so the count is asserted rather than trusted.
        Assert.True(files.Length > 1000, $"only {files.Length} library sources found - wrong root?");

        return files
            .Select(path => (path, (CompilationUnitSyntax)CSharpSyntaxTree.ParseText(File.ReadAllText(path)).GetRoot()))
            .ToArray();
    }

    /// <summary>
    /// Every offending pair, as "file(line): the call, then the read".
    /// </summary>
    private static (IReadOnlyList<string> Offences, int Declared) Walk(
        IReadOnlyList<(string Path, CompilationUnitSyntax Root)> sources)
    {
        // The population comes from the artefact, never from a list somebody appends to: a method declared
        // on an interface is a method a host can supply the body of.
        var seamMethods = sources
            .SelectMany(s => s.Root.DescendantNodes().OfType<InterfaceDeclarationSyntax>())
            .SelectMany(i => i.Members.OfType<MethodDeclarationSyntax>())
            .Select(m => m.Identifier.ValueText)
            .ToHashSet(StringComparer.Ordinal);

        var mutableMembers = sources
            .SelectMany(s => s.Root.DescendantNodes())
            .SelectMany(node => node switch
            {
                PropertyDeclarationSyntax p when IsMutableInPlace(p.Type) => new[] { p.Identifier.ValueText },
                FieldDeclarationSyntax f when IsMutableInPlace(f.Declaration.Type)
                    => f.Declaration.Variables.Select(v => v.Identifier.ValueText).ToArray(),
                ParameterSyntax r when IsMutableInPlace(r.Type) => [r.Identifier.ValueText],
                _ => [],
            })
            .ToHashSet(StringComparer.Ordinal);

        var offences = new List<string>();
        var declared = 0;

        foreach (var (path, root) in sources)
        foreach (var body in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (body.Body is not { } statements) continue;

            foreach (var awaited in statements.DescendantNodes().OfType<AwaitExpressionSyntax>())
            {
                if (awaited.Expression is not InvocationExpressionSyntax
                    {
                        Expression: MemberAccessExpressionSyntax { Name.Identifier.ValueText: var called },
                    } call)
                    continue;

                if (!seamMethods.Contains(called)) continue;

                foreach (var argument in call.ArgumentList.Arguments)
                {
                    var lent = Normalized(argument.Expression);
                    if (lent.Length == 0 || argument.Expression is LiteralExpressionSyntax) continue;

                    var readBack = statements
                        .DescendantNodes()
                        .Where(node => node.SpanStart > awaited.Span.End)
                        .OfType<MemberAccessExpressionSyntax>()
                        .FirstOrDefault(access =>
                            mutableMembers.Contains(access.Name.Identifier.ValueText)
                            && (Normalized(access) == lent
                                || Normalized(access).StartsWith(lent + ".", StringComparison.Ordinal)));

                    if (readBack is null) continue;

                    if (IsDeclared(call, readBack.Name.Identifier.ValueText))
                    {
                        declared++;
                        break;
                    }

                    var lentAt = call.SyntaxTree.GetLineSpan(call.Span).StartLinePosition.Line + 1;
                    var readAt = readBack.SyntaxTree.GetLineSpan(readBack.Span).StartLinePosition.Line + 1;
                    offences.Add(
                        $"{Path.GetFileName(path)}({lentAt}): {called} was handed {lent}, "
                        + $"then line {readAt} read {Normalized(readBack)}");
                    break;
                }
            }
        }

        return (offences, declared);
    }

    /// <summary>
    /// Nothing hands a value to a replaceable implementation and then measures anything against it.
    /// </summary>
    [Fact]
    public void NothingIsMeasuredAgainstAValueAlreadyLentOut()
    {
        var (offences, _) = Walk(LibrarySources());

        Assert.True(
            offences.Count == 0,
            "A value was handed to an implementation a host can replace, and then read back:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, offences));
    }

    /// <summary>
    /// Every declaration that the read-back is deliberate describes a read-back that is still there.
    /// </summary>
    /// <remarks>
    /// A marker is a silence, so it has to expire on its own. Left behind by an edit that removed the
    /// read it excused, it would go on excusing whatever lands there next - and the walker would report
    /// clean about a site nobody has looked at since.
    /// </remarks>
    [Fact]
    public void EveryDeclarationOfADeliberateLoanStillDescribesOne()
    {
        var sources = LibrarySources();
        var (_, declared) = Walk(sources);

        var written = sources
            .SelectMany(s => s.Root.DescendantTrivia())
            .Count(trivia => trivia.ToString().Contains(Declared, StringComparison.Ordinal));

        Assert.Equal(written, declared);
    }

    /// <summary>
    /// What this walker is blind to, said out loud so a clean run is not read as a clean repository.
    /// </summary>
    /// <remarks>
    /// It sees only awaited calls, so a synchronous seam passes; only calls written as a member access, so
    /// one through a delegate or an extension-method chain passes; and only reads in the same method body,
    /// so a value stored on a field and read by another member passes. It also decides mutability from the
    /// declared type text rather than from a resolved symbol, so a type alias or a custom collection is not
    /// recognised.
    /// </remarks>
    [Fact]
    public void TheShapesThisTestCannotSee()
    {
        // A statement of scope rather than a check, and it is here so the list has a place a reader lands
        // on from the failure message above.
        Assert.True(true);
    }
}
