// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The hierarchy helpers: walking a chain of parents upwards, flattening a tree breadth-first, and the queue
/// fill both flattening overloads are built on.
/// </summary>
/// <remarks>
/// These are public members of a published package that nothing in this library calls yet and that are
/// deliberately retained. Exercised here rather than left for whoever calls them first, because both walks
/// have a way of not terminating: <c>TravelUp</c> on a node that is its own parent, and the flatten on a tree
/// whose children point back at their ancestors. The first is guarded and asserted below; the second is not
/// guarded, which the cycle case records as the contract rather than pretending otherwise.
/// </remarks>
public class EnumerableExtensionsTests
{
    private sealed class Node(string name, Node? parent = null)
    {
        public string Name { get; } = name;
        public Node? Parent { get; set; } = parent;
        public List<Node> Children { get; } = [];
    }

    [Fact]
    public void TravelUp_YieldsTheItemThenEveryAncestor()
    {
        var root = new Node("root");
        var middle = new Node("middle", root);
        var leaf = new Node("leaf", middle);

        var path = leaf.TravelUp(node => node.Parent).Select(node => node.Name);

        Assert.Equal(["leaf", "middle", "root"], path);
    }

    /// <summary>
    /// A node that is its own parent is how a badly built hierarchy spells the top, and the walk stops there
    /// rather than yielding it forever. Without this guard the sequence never ends, and a caller enumerating
    /// it hangs instead of failing.
    /// </summary>
    [Fact]
    public void TravelUp_StopsAtANodeThatIsItsOwnParent()
    {
        var root = new Node("root");
        root.Parent = root;

        Assert.Equal(["root"], root.TravelUp(node => node.Parent).Select(node => node.Name));
    }

    [Fact]
    public void FlattenTree_FromRoots_WalksBreadthFirst()
    {
        var a = new Node("a");
        var b = new Node("b");
        a.Children.Add(new Node("a1"));
        a.Children.Add(new Node("a2"));
        b.Children.Add(new Node("b1"));
        a.Children[0].Children.Add(new Node("a1x"));

        var flat = new[] { a, b }.FlattenTree(node => node.Children).Select(node => node.Name);

        // Breadth-first, so every node of one depth precedes any node of the next.
        Assert.Equal(["a", "b", "a1", "a2", "b1", "a1x"], flat);
    }

    [Fact]
    public void FlattenTree_FromASingleRoot_WalksBreadthFirst()
    {
        var root = new Node("root");
        root.Children.Add(new Node("first"));
        root.Children.Add(new Node("second"));
        root.Children[0].Children.Add(new Node("deep"));

        var flat = root.FlattenTree(node => node.Children).Select(node => node.Name);

        Assert.Equal(["root", "first", "second", "deep"], flat);
    }

    [Fact]
    public void FlattenTree_OfNothing_YieldsNothing()
        => Assert.Empty(((IEnumerable<Node>?)null).FlattenTree(node => node.Children));

    [Fact]
    public void EnqueueAll_AppendsInOrder()
    {
        var queue = new Queue<string>();
        queue.Enqueue("first");

        queue.EnqueueAll(["second", "third"]);

        Assert.Equal(["first", "second", "third"], queue);
    }

    /// <summary>
    /// An absent collection leaves the queue alone rather than throwing, which is what lets the flatten
    /// overloads pass a possibly-null root set straight through.
    /// </summary>
    [Fact]
    public void EnqueueAll_OfNothing_LeavesTheQueueAlone()
    {
        var queue = new Queue<string>();
        queue.Enqueue("only");

        queue.EnqueueAll(null);

        Assert.Equal(["only"], queue);
    }
}
