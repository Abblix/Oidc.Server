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
/// the text. What it does NOT see is listed on <see cref="TheShapesThisWalkerCannotSee"/>, and what it
/// cannot even READ is asserted by <see cref="EverySourceIsParsedOrKnownToBeUnreadable"/>.
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
    /// The marker a site uses to say that touching the value afterwards is the point, and why.
    /// </summary>
    /// <remarks>
    /// Reading a value back after handing it to a store is sometimes the whole intent - echoing what was
    /// registered, including the defaults the server assigned - and so is writing the change that gets
    /// persisted. The walker cannot tell either from a yardstick somebody moved, so the site says which
    /// it is, at the site, with a reason.
    /// <para>
    /// The marker NAMES the members it excuses, comma-separated, so it stays a silence about those and not
    /// about the call: a read of anything else is reported as if the marker were not there. And every name
    /// it carries must match a read that is still there, so a marker outliving what it excused fails
    /// rather than going on excusing whatever lands next.
    /// </para>
    /// </remarks>
    private const string Declared = "lent deliberately ";

    /// <summary>The members a statement declares, as written above it.</summary>
    /// <remarks>
    /// The comment block above the statement is read as ONE line, so a list too long for a line of code
    /// wraps the way prose does. The names run to the colon, and what follows the colon is the reason,
    /// which nothing here reads - it is for whoever arrives at the site.
    /// </remarks>
    private static string[] MembersDeclaredOn(SyntaxNode statement)
    {
        var joined = string.Join(' ', statement.GetLeadingTrivia()
            .Where(trivia => trivia.IsKind(SyntaxKind.SingleLineCommentTrivia))
            .Select(trivia => trivia.ToString().Trim()[2..]));

        if (!joined.Contains(Declared, StringComparison.Ordinal)) return [];

        var start = joined.IndexOf(Declared, StringComparison.Ordinal);
        if (start < 0) return [];

        var names = joined[(start + Declared.Length)..];
        var end = names.IndexOf(':');
        return end < 0
            ? []
            : names[..end].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>The statement a call belongs to, which is what a declaration is attached to.</summary>
    private static StatementSyntax? EnclosingStatement(SyntaxNode call)
    {
        for (var node = call; node is not null; node = node.Parent)
        {
            if (node is StatementSyntax statement) return statement;
        }

        return null;
    }

    /// <summary>One site and member, named the same way wherever it is counted.</summary>
    /// <remarks>
    /// Built once and used by both sides. Two keys assembled independently agree only while nothing
    /// moves: one built from the call and one from the statement disagree the moment a statement wraps,
    /// and one carrying a full path disagrees on whichever platform does not spell paths that way.
    /// </remarks>
    private static string SiteOf(StatementSyntax statement, string member)
    {
        var line = statement.SyntaxTree.GetLineSpan(statement.Span).StartLinePosition.Line + 1;
        return $"{Path.GetFileName(statement.SyntaxTree.FilePath)}({line}):{member}";
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }

    private static IReadOnlyList<(string Path, SyntaxTree Tree)> LibrarySources()
    {
        var source = Path.Combine(RepositoryRoot(), "src");
        var files = Directory
            .EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                           && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .ToArray();

        // A file that cannot be read hides every occurrence in it from every walker, and reads exactly like
        // a clean one - so the count is asserted rather than trusted. It is a weak control on its own; the
        // one that proves the matcher reaches a positive is the declaration count.
        Assert.True(files.Length > 1000, $"only {files.Length} library sources found - wrong root?");

        return files
            // The path travels with the tree, so a node can say which file it came from - two of the
            // assertions below name a site, and a tree parsed without one names nothing.
            .Select(path => (path, CSharpSyntaxTree.ParseText(File.ReadAllText(path), path: path)))
            .ToArray();
    }

    private static IEnumerable<SyntaxNode> After(SyntaxNode body, SyntaxNode call)
        => body.DescendantNodes().Where(node => node.SpanStart > call.Span.End);

    /// <summary>
    /// Every lendable member of <paramref name="lent"/> read after the call, once each.
    /// </summary>
    /// <remarks>
    /// Two shapes, because the repository writes both: an ordinary member access, and a property pattern,
    /// where the member never appears as an access rooted at the value - <c>x is { Members.Count: 0 }</c>
    /// carries the same read and none of the syntax the first shape is found by.
    /// </remarks>
    private static IEnumerable<(string Member, SyntaxNode Where)> ReadsAfter(
        SyntaxNode body, SyntaxNode call, string lent, IReadOnlySet<string> lendable)
    {
        var found = new Dictionary<string, SyntaxNode>(StringComparer.Ordinal);

        bool RootedAtTheLoan(SyntaxNode expression)
        {
            var text = Normalized(expression);
            return text == lent || text.StartsWith(lent + ".", StringComparison.Ordinal);
        }

        foreach (var access in After(body, call).OfType<MemberAccessExpressionSyntax>())
        {
            var member = access.Name.Identifier.ValueText;
            if (lendable.Contains(member) && RootedAtTheLoan(access))
                found.TryAdd(member, access);
        }

        IEnumerable<(SyntaxNode Subject, PatternSyntax Pattern)> Patterns()
        {
            foreach (var node in After(body, call))
                switch (node)
                {
                    case IsPatternExpressionSyntax test:
                        yield return (test.Expression, test.Pattern);
                        break;

                    case SwitchExpressionSyntax choice:
                        foreach (var arm in choice.Arms)
                            yield return (choice.GoverningExpression, arm.Pattern);
                        break;

                    case SwitchStatementSyntax choice:
                        foreach (var label in choice.Sections
                            .SelectMany(section => section.Labels)
                            .OfType<CasePatternSwitchLabelSyntax>())
                            yield return (choice.Expression, label.Pattern);
                        break;
                }
        }

        foreach (var (subject, pattern) in Patterns())
        {
            if (!RootedAtTheLoan(subject)) continue;

            // Only a PROPERTY pattern names members. The elements of a positional one carry the names
            // of deconstruction parameters, which read like members and are not.
            foreach (var named in pattern.DescendantNodesAndSelf()
                .OfType<SubpatternSyntax>()
                .Where(sub => sub.Parent is PropertyPatternClauseSyntax))
            {
                var member = named switch
                {
                    { NameColon: { } name } => name.Name.Identifier.ValueText,
                    { ExpressionColon.Expression: IdentifierNameSyntax id } => id.Identifier.ValueText,
                    { ExpressionColon.Expression: MemberAccessExpressionSyntax access }
                        => Normalized(access).Split('.')[0],
                    _ => null,
                };

                if (member is not null && lendable.Contains(member))
                    found.TryAdd(member, named);
            }
        }

        return found.Select(entry => (entry.Key, entry.Value));
    }

    /// <summary>How many calls a host could answer this statement makes.</summary>
    private static int SeamCallsIn(SyntaxNode statement, IReadOnlySet<string> seamMethods)
        => statement.DescendantNodes()
            .OfType<AwaitExpressionSyntax>()
            .Select(awaited => awaited.Expression)
            .OfType<InvocationExpressionSyntax>()
            .Count(call => call.Expression is MemberAccessExpressionSyntax access
                           && seamMethods.Contains(access.Name.Identifier.ValueText));

    /// <summary>
    /// Every offence, and every declared member that still describes a read.
    /// </summary>
    private static (IReadOnlyList<string> Offences, IReadOnlySet<string> Honoured) Walk(
        IReadOnlyList<(string Path, SyntaxTree Tree)> sources)
    {
        var roots = sources.Select(s => (s.Path, Root: s.Tree.GetRoot())).ToArray();

        // The population comes from the artefact, never from a list somebody appends to: a method declared
        // on an interface is a method a host can supply the body of.
        var seamMethods = roots
            .SelectMany(s => s.Root.DescendantNodes().OfType<InterfaceDeclarationSyntax>())
            .SelectMany(i => i.Members.OfType<MethodDeclarationSyntax>())
            .Select(m => m.Identifier.ValueText)
            .ToHashSet(StringComparer.Ordinal);

        var lendable = roots
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
        var honoured = new HashSet<string>(StringComparer.Ordinal);

        // The refusal below belongs to the STATEMENT, and the loop reaches it once per call on it.
        var refused = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (path, root) in roots)
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (method.Body is not { } body) continue;

            foreach (var awaited in body.DescendantNodes().OfType<AwaitExpressionSyntax>())
            {
                if (awaited.Expression is not InvocationExpressionSyntax
                    {
                        Expression: MemberAccessExpressionSyntax { Name.Identifier.ValueText: var called },
                    } call)
                    continue;

                if (!seamMethods.Contains(called)) continue;

                if (EnclosingStatement(call) is not { } statement) continue;

                var declared = MembersDeclaredOn(statement);
                var lentAt = statement.SyntaxTree.GetLineSpan(statement.Span).StartLinePosition.Line + 1;

                // A declaration is attached to a statement, so a statement carrying two seam calls would
                // have one declaration excusing both. Refused rather than silently obeyed: the marker
                // says which members it excuses and cannot say which call it means.
                if (declared.Length > 0 && SeamCallsIn(statement, seamMethods) > 1)
                {
                    if (refused.Add($"{path}({lentAt})"))
                        offences.Add(
                            $"{Path.GetFileName(path)}({lentAt}): a deliberate loan is declared on a "
                            + "statement carrying more than one call, so it cannot say which one it excuses");

                    continue;
                }

                foreach (var argument in call.ArgumentList.Arguments)
                {
                    if (argument.Expression is LiteralExpressionSyntax) continue;

                    var lent = Normalized(argument.Expression);
                    if (lent.Length == 0) continue;

                    foreach (var (member, where) in ReadsAfter(body, awaited, lent, lendable))
                    {
                        if (declared.Contains(member))
                        {
                            honoured.Add(SiteOf(statement, member));
                            continue;
                        }

                        var readAt = where.SyntaxTree.GetLineSpan(where.Span).StartLinePosition.Line + 1;
                        offences.Add(
                            $"{Path.GetFileName(path)}({lentAt}): {called} was handed {lent}, "
                            + $"then line {readAt} read {member}");
                    }
                }
            }
        }

        return (offences, honoured);
    }

    /// <summary>
    /// One source of its own, so the walker's reach is pinned by what it CAN see rather than by what
    /// the library happens to contain today.
    /// </summary>
    /// <remarks>
    /// A capability proved only by a real site stops being proved the moment that site is rewritten, and
    /// the walker then loses it silently - which is the failure it exists to catch, in the instrument.
    /// The probe declares its own seam and its own lendable member, so nothing about it depends on the
    /// library either.
    /// </remarks>
    private static IReadOnlyList<string> OffencesIn(string body, string declaration = "")
    {
        var source = $$"""
                       using System.Threading.Tasks;

                       interface ISeam { Task KeepAsync(Thing thing); }

                       class Thing { public string[] Names { get; set; } = []; }

                       class Caller
                       {
                           private readonly ISeam seam = null!;

                           public async Task Run(Thing thing, Thing other)
                           {
                               {{declaration}}
                               {{body}}
                           }
                       }
                       """;

        var tree = CSharpSyntaxTree.ParseText(source, path: "Probe.cs");
        Assert.DoesNotContain(tree.GetDiagnostics(), d => d.Severity == DiagnosticSeverity.Error);

        return Walk([("Probe.cs", tree)]).Offences;
    }

    /// <summary>Every spelling of the same read that the walker claims to catch.</summary>
    [Theory]
    [InlineData("var n = thing.Names.Length;")]
    [InlineData("if (thing is { Names.Length: 0 }) { }")]
    [InlineData("var n = thing switch { { Names.Length: 0 } => 1, _ => 2 };")]
    [InlineData("switch (thing) { case { Names.Length: 0 }: break; }")]
    public void AReadAfterTheLoanIsCaughtHoweverItIsWritten(string read)
    {
        var offences = OffencesIn($"await seam.KeepAsync(thing);{Environment.NewLine}{read}");

        Assert.Single(offences);
        Assert.Contains("read Names", offences[0], StringComparison.Ordinal);
    }

    /// <summary>What the walker must NOT report, so its silence means something.</summary>
    [Theory]
    // Read before the loan: the callee never had the chance.
    [InlineData("var n = thing.Names.Length;\nawait seam.KeepAsync(thing);", "")]
    // Another object entirely.
    [InlineData("await seam.KeepAsync(thing);\nvar n = other.Names.Length;", "")]
    // A positional pattern names deconstruction parameters, which read like members and are not.
    [InlineData("await seam.KeepAsync(thing);\nif (thing is (Names: 1, Other: 2)) { }", "")]
    // Declared, and the declaration names the member.
    [InlineData("await seam.KeepAsync(thing);\nvar n = thing.Names.Length;", "// lent deliberately Names: the reason.")]
    public void WhatIsNotAnOffence(string body, string declaration)
        => Assert.Empty(OffencesIn(body.Replace("\\n", Environment.NewLine), declaration));

    /// <summary>A declaration only counts where a declaration is written.</summary>
    /// <remarks>
    /// A documentation comment opens with the same two characters, and the tools that read documentation
    /// put it where a reader of the code does not look for a decision about the code.
    /// </remarks>
    [Fact]
    public void ADeclarationInADocumentationCommentDoesNotSilence()
    {
        var offences = OffencesIn(
            $"await seam.KeepAsync(thing);{Environment.NewLine}var n = thing.Names.Length;",
            "/// lent deliberately Names: written where it does not belong.");

        Assert.Single(offences);
    }

    /// <summary>A declaration on a statement making two calls cannot say which one it excuses.</summary>
    [Fact]
    public void ADeclarationOnAStatementWithTwoCallsIsRefused()
    {
        var offences = OffencesIn(
            $"var pair = (await seam.KeepAsync(thing), await seam.KeepAsync(other));"
            + $"{Environment.NewLine}var n = thing.Names.Length;",
            "// lent deliberately Names: written for the first call only.");

        Assert.Single(offences);
        Assert.Contains("more than one call", offences[0], StringComparison.Ordinal);
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
    /// Every member a site declares deliberate is a member it still reads.
    /// </summary>
    /// <remarks>
    /// A marker is a silence, so it has to expire on its own. Left behind by an edit that removed the read
    /// it excused, it would go on excusing whatever lands there next - and the walker would report clean
    /// about a site nobody has looked at since. This is also the walker's real positive control: it proves
    /// the matcher reaches a positive on named sites, which a file count cannot.
    /// </remarks>
    [Fact]
    public void EveryDeclaredMemberStillDescribesARead()
    {
        var sources = LibrarySources();
        var (_, honoured) = Walk(sources);

        // Counted the way the walker reads them, over the same statements, so the two cannot disagree
        // about what a declaration says - only about whether it still describes anything.
        var written = sources
            .SelectMany(s => s.Tree.GetRoot().DescendantNodes().OfType<StatementSyntax>())
            .SelectMany(statement => MembersDeclaredOn(statement)
                .Select(member => SiteOf(statement, member)))
            .ToArray();

        Assert.True(
            written.Length > 0,
            "no site declares a deliberate loan, so nothing proves the walker matches");

        // Named rather than counted: a number tells you the two disagree, and the name tells you which
        // declaration stopped describing a read.
        var stale = written.Where(entry => !honoured.Contains(entry)).Order().ToArray();

        Assert.True(
            stale.Length == 0,
            "A site declares a deliberate loan of a member it no longer reads:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, stale));
    }

    /// <summary>
    /// Every source parses, except the ones this walker knows its parser is too old to read.
    /// </summary>
    /// <remarks>
    /// Syntax-tree error recovery is silent: a file the parser cannot read produces a tree with nothing in
    /// it and is walked exactly like an empty one, so the walker reports clean about whatever it contains.
    /// The analyzer package pinned for this suite predates the union syntax the library is written in,
    /// which is why the list below is not empty.
    /// <para>
    /// The list is exact on purpose. When the parser learns the syntax, this assertion is what fails, and
    /// the failure says to delete the entry rather than leaving a permanent hole nobody re-reads.
    /// </para>
    /// </remarks>
    [Fact]
    public void EverySourceIsParsedOrKnownToBeUnreadable()
    {
        var root = RepositoryRoot();
        var unreadable = LibrarySources()
            .Where(s => s.Tree.GetDiagnostics().Any(d => d.Severity == DiagnosticSeverity.Error))
            .Select(s => Path.GetRelativePath(root, s.Path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["src/Abblix.Utils/Result.cs"], unreadable);
    }

    /// <summary>
    /// What this walker is blind to, said out loud so a clean run is not read as a clean repository.
    /// </summary>
    /// <remarks>
    /// It sees only awaited calls, so a synchronous seam passes; only calls written as a member access, so
    /// one through a delegate or an extension-method chain passes; and only reads in the same method body,
    /// so a value stored on a field and read by another member passes. A read reached through a LOCAL ALIAS
    /// passes as well, since the walker matches the text of the expression rather than following what it
    /// refers to, and one assignment defeats it. It also decides lendability from the declared type text
    /// rather than from a resolved symbol, so a type alias or a custom collection is not recognised, while
    /// a name declared mutably ANYWHERE counts as mutable everywhere - which errs towards reporting.
    /// <para>
    /// It reports on branches that cannot both run, since it compares positions rather than paths.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheShapesThisWalkerCannotSee()
    {
        // A statement of scope rather than a check, and it is here so the list has a place a reader lands
        // on from the failure message above.
        Assert.True(true);
    }
}
