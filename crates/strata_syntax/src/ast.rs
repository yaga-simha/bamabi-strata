//! Typed `rowan` AST wrappers over the lossless Strata v2.0 CST.

use crate::syntax_kind::{SyntaxKind, SyntaxNode, SyntaxToken};
use rowan::{NodeOrToken, TextRange};

/// Trait implemented by typed AST node wrappers backed by a [`SyntaxNode`].
pub trait AstNode: Sized {
    /// Returns `true` if `kind` corresponds to this AST node type.
    fn can_cast(kind: SyntaxKind) -> bool;

    /// Attempts to wrap `syntax` into `Self`, returning `None` if its kind does not match.
    fn cast(syntax: SyntaxNode) -> Option<Self>;

    /// Returns the underlying untyped CST [`SyntaxNode`].
    fn syntax(&self) -> &SyntaxNode;

    /// Returns the source byte range spanned by this AST node.
    #[inline]
    fn text_range(&self) -> TextRange {
        self.syntax().text_range()
    }
}

macro_rules! ast_node {
    ($name:ident, $kind:ident) => {
        #[doc = concat!("Typed AST wrapper for `SyntaxKind::", stringify!($kind), "`.")]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name {
            syntax: SyntaxNode,
        }

        impl AstNode for $name {
            #[inline]
            fn can_cast(kind: SyntaxKind) -> bool {
                kind == SyntaxKind::$kind
            }

            #[inline]
            fn cast(syntax: SyntaxNode) -> Option<Self> {
                Self::can_cast(syntax.kind()).then_some(Self { syntax })
            }

            #[inline]
            fn syntax(&self) -> &SyntaxNode {
                &self.syntax
            }
        }
    };
}

ast_node!(SourceFile, SourceFile);
ast_node!(Attribute, Attribute);
ast_node!(AttrArgList, AttrArgList);
ast_node!(AttrArg, AttrArg);
ast_node!(ModuleDecl, ModuleDecl);
ast_node!(ImportDecl, ImportDecl);
ast_node!(SemVer, SemVer);
ast_node!(Path, Path);
ast_node!(GenericParams, GenericParams);
ast_node!(GenericArgs, GenericArgs);
ast_node!(ConstDecl, ConstDecl);
ast_node!(StructDecl, StructDecl);
ast_node!(EnumDecl, EnumDecl);
ast_node!(VariantDecl, VariantDecl);
ast_node!(ComponentDecl, ComponentDecl);
ast_node!(StratumBlock, StratumBlock);
ast_node!(RequireClause, RequireClause);
ast_node!(RequireItem, RequireItem);
ast_node!(TagDecl, TagDecl);
ast_node!(ResourceDecl, ResourceDecl);
ast_node!(EventDecl, EventDecl);
ast_node!(StreamDecl, StreamDecl);
ast_node!(RpcDecl, RpcDecl);
ast_node!(RelationDecl, RelationDecl);
ast_node!(RelFlags, RelFlags);
ast_node!(TableDecl, TableDecl);
ast_node!(TableRow, TableRow);
ast_node!(CurveDecl, CurveDecl);
ast_node!(CurvePoint, CurvePoint);
ast_node!(FieldDecl, FieldDecl);
ast_node!(FieldInitList, FieldInitList);
ast_node!(FieldInit, FieldInit);
ast_node!(SpatialGridDecl, SpatialGridDecl);
ast_node!(SpatialHistoryDecl, SpatialHistoryDecl);
ast_node!(HashIndexDecl, HashIndexDecl);
ast_node!(AspectDecl, AspectDecl);
ast_node!(PrefabDecl, PrefabDecl);
ast_node!(ObjectDecl, ObjectDecl);
ast_node!(ZoneDecl, ZoneDecl);
ast_node!(CompInitList, CompInitList);
ast_node!(CompInit, CompInit);
ast_node!(TimelineDecl, TimelineDecl);
ast_node!(TimelineWindow, TimelineWindow);
ast_node!(TimelineAt, TimelineAt);
ast_node!(TaskDecl, TaskDecl);
ast_node!(FsmDecl, FsmDecl);
ast_node!(StateDecl, StateDecl);
ast_node!(TransitionDecl, TransitionDecl);
ast_node!(SysDecl, SysDecl);
ast_node!(ObsDecl, ObsDecl);
ast_node!(FnDecl, FnDecl);
ast_node!(MigrateDecl, MigrateDecl);
ast_node!(ParamList, ParamList);
ast_node!(Param, Param);
ast_node!(SysParamList, SysParamList);
ast_node!(SysParam, SysParam);
ast_node!(ProjTermList, ProjTermList);
ast_node!(ProjTerm, ProjTerm);
ast_node!(EffectsClause, EffectsClause);
ast_node!(EffectEntry, EffectEntry);
ast_node!(ScheduleDecl, ScheduleDecl);
ast_node!(ScheduleMod, ScheduleMod);
ast_node!(ScheduleNode, ScheduleNode);
ast_node!(AssertLayoutDecl, AssertLayoutDecl);
ast_node!(AssertParDecl, AssertParDecl);
ast_node!(SimTestDecl, SimTestDecl);
ast_node!(NetSimTestDecl, NetSimTestDecl);
ast_node!(NetSimParamList, NetSimParamList);
ast_node!(NetSimParam, NetSimParam);
ast_node!(TypeRef, TypeRef);
ast_node!(ArrayType, ArrayType);
ast_node!(RefType, RefType);
ast_node!(PtrTermType, PtrTermType);
ast_node!(TupleType, TupleType);
ast_node!(Block, Block);
ast_node!(LetStmt, LetStmt);
ast_node!(UniformLetStmt, UniformLetStmt);
ast_node!(AbortIfStmt, AbortIfStmt);
ast_node!(RaceStmt, RaceStmt);
ast_node!(BranchStmt, BranchStmt);
ast_node!(WaitStmt, WaitStmt);
ast_node!(WaitUntilStmt, WaitUntilStmt);
ast_node!(YieldTickStmt, YieldTickStmt);
ast_node!(AtomicStmt, AtomicStmt);
ast_node!(ForExpr, ForExpr);
ast_node!(ReduceClause, ReduceClause);
ast_node!(ReduceEntry, ReduceEntry);
ast_node!(IfExpr, IfExpr);
ast_node!(PostfixCallExpr, PostfixCallExpr);
ast_node!(SpawnExpr, SpawnExpr);
ast_node!(SpawnBatchExpr, SpawnBatchExpr);
ast_node!(DespawnAllExpr, DespawnAllExpr);
ast_node!(InsertExpr, InsertExpr);
ast_node!(RemoveExpr, RemoveExpr);
ast_node!(ArgList, ArgList);

/// Enumerated top-level item declarations inside a [`SourceFile`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Item {
    Module(ModuleDecl),
    Import(ImportDecl),
    Const(ConstDecl),
    Struct(StructDecl),
    Enum(EnumDecl),
    Component(ComponentDecl),
    Tag(TagDecl),
    Resource(ResourceDecl),
    Event(EventDecl),
    Stream(StreamDecl),
    Rpc(RpcDecl),
    Relation(RelationDecl),
    Table(TableDecl),
    Curve(CurveDecl),
    SpatialGrid(SpatialGridDecl),
    SpatialHistory(SpatialHistoryDecl),
    HashIndex(HashIndexDecl),
    Aspect(AspectDecl),
    Prefab(PrefabDecl),
    Object(ObjectDecl),
    Zone(ZoneDecl),
    Timeline(TimelineDecl),
    Task(TaskDecl),
    Fsm(FsmDecl),
    Sys(SysDecl),
    Obs(ObsDecl),
    Fn(FnDecl),
    Migrate(MigrateDecl),
    Schedule(ScheduleDecl),
    AssertLayout(AssertLayoutDecl),
    AssertPar(AssertParDecl),
    SimTest(SimTestDecl),
    NetSimTest(NetSimTestDecl),
}

impl Item {
    /// Casts a CST [`SyntaxNode`] to a typed top-level [`Item`].
    pub fn cast(node: SyntaxNode) -> Option<Self> {
        match node.kind() {
            SyntaxKind::ModuleDecl => Some(Self::Module(ModuleDecl { syntax: node })),
            SyntaxKind::ImportDecl => Some(Self::Import(ImportDecl { syntax: node })),
            SyntaxKind::ConstDecl => Some(Self::Const(ConstDecl { syntax: node })),
            SyntaxKind::StructDecl => Some(Self::Struct(StructDecl { syntax: node })),
            SyntaxKind::EnumDecl => Some(Self::Enum(EnumDecl { syntax: node })),
            SyntaxKind::ComponentDecl => Some(Self::Component(ComponentDecl { syntax: node })),
            SyntaxKind::TagDecl => Some(Self::Tag(TagDecl { syntax: node })),
            SyntaxKind::ResourceDecl => Some(Self::Resource(ResourceDecl { syntax: node })),
            SyntaxKind::EventDecl => Some(Self::Event(EventDecl { syntax: node })),
            SyntaxKind::StreamDecl => Some(Self::Stream(StreamDecl { syntax: node })),
            SyntaxKind::RpcDecl => Some(Self::Rpc(RpcDecl { syntax: node })),
            SyntaxKind::RelationDecl => Some(Self::Relation(RelationDecl { syntax: node })),
            SyntaxKind::TableDecl => Some(Self::Table(TableDecl { syntax: node })),
            SyntaxKind::CurveDecl => Some(Self::Curve(CurveDecl { syntax: node })),
            SyntaxKind::SpatialGridDecl => {
                Some(Self::SpatialGrid(SpatialGridDecl { syntax: node }))
            }
            SyntaxKind::SpatialHistoryDecl => {
                Some(Self::SpatialHistory(SpatialHistoryDecl { syntax: node }))
            }
            SyntaxKind::HashIndexDecl => Some(Self::HashIndex(HashIndexDecl { syntax: node })),
            SyntaxKind::AspectDecl => Some(Self::Aspect(AspectDecl { syntax: node })),
            SyntaxKind::PrefabDecl => Some(Self::Prefab(PrefabDecl { syntax: node })),
            SyntaxKind::ObjectDecl => Some(Self::Object(ObjectDecl { syntax: node })),
            SyntaxKind::ZoneDecl => Some(Self::Zone(ZoneDecl { syntax: node })),
            SyntaxKind::TimelineDecl => Some(Self::Timeline(TimelineDecl { syntax: node })),
            SyntaxKind::TaskDecl => Some(Self::Task(TaskDecl { syntax: node })),
            SyntaxKind::FsmDecl => Some(Self::Fsm(FsmDecl { syntax: node })),
            SyntaxKind::SysDecl => Some(Self::Sys(SysDecl { syntax: node })),
            SyntaxKind::ObsDecl => Some(Self::Obs(ObsDecl { syntax: node })),
            SyntaxKind::FnDecl => Some(Self::Fn(FnDecl { syntax: node })),
            SyntaxKind::MigrateDecl => Some(Self::Migrate(MigrateDecl { syntax: node })),
            SyntaxKind::ScheduleDecl => Some(Self::Schedule(ScheduleDecl { syntax: node })),
            SyntaxKind::AssertLayoutDecl => {
                Some(Self::AssertLayout(AssertLayoutDecl { syntax: node }))
            }
            SyntaxKind::AssertParDecl => Some(Self::AssertPar(AssertParDecl { syntax: node })),
            SyntaxKind::SimTestDecl => Some(Self::SimTest(SimTestDecl { syntax: node })),
            SyntaxKind::NetSimTestDecl => Some(Self::NetSimTest(NetSimTestDecl { syntax: node })),
            _ => None,
        }
    }

    /// Returns the underlying CST node for this item.
    pub fn syntax(&self) -> &SyntaxNode {
        match self {
            Self::Module(n) => n.syntax(),
            Self::Import(n) => n.syntax(),
            Self::Const(n) => n.syntax(),
            Self::Struct(n) => n.syntax(),
            Self::Enum(n) => n.syntax(),
            Self::Component(n) => n.syntax(),
            Self::Tag(n) => n.syntax(),
            Self::Resource(n) => n.syntax(),
            Self::Event(n) => n.syntax(),
            Self::Stream(n) => n.syntax(),
            Self::Rpc(n) => n.syntax(),
            Self::Relation(n) => n.syntax(),
            Self::Table(n) => n.syntax(),
            Self::Curve(n) => n.syntax(),
            Self::SpatialGrid(n) => n.syntax(),
            Self::SpatialHistory(n) => n.syntax(),
            Self::HashIndex(n) => n.syntax(),
            Self::Aspect(n) => n.syntax(),
            Self::Prefab(n) => n.syntax(),
            Self::Object(n) => n.syntax(),
            Self::Zone(n) => n.syntax(),
            Self::Timeline(n) => n.syntax(),
            Self::Task(n) => n.syntax(),
            Self::Fsm(n) => n.syntax(),
            Self::Sys(n) => n.syntax(),
            Self::Obs(n) => n.syntax(),
            Self::Fn(n) => n.syntax(),
            Self::Migrate(n) => n.syntax(),
            Self::Schedule(n) => n.syntax(),
            Self::AssertLayout(n) => n.syntax(),
            Self::AssertPar(n) => n.syntax(),
            Self::SimTest(n) => n.syntax(),
            Self::NetSimTest(n) => n.syntax(),
        }
    }
}

/// Returns child nodes of type `N` inside `parent`.
pub fn children<N: AstNode>(parent: &SyntaxNode) -> impl Iterator<Item = N> {
    parent.children().filter_map(N::cast)
}

/// Returns the first child node of type `N` inside `parent`.
pub fn child<N: AstNode>(parent: &SyntaxNode) -> Option<N> {
    parent.children().find_map(N::cast)
}

/// Returns the first direct `Ident` token inside `node`.
pub fn first_ident(node: &SyntaxNode) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(|el| el.into_token())
        .find(|tok| tok.kind() == SyntaxKind::Ident)
}

/// Collects all `@attr` nodes directly attached to `node`.
pub fn attrs(node: &SyntaxNode) -> Vec<Attribute> {
    children(node).collect()
}

/// Extracts an attribute's identifier name (e.g. `"soa"`, `"par"`, `"version"`).
pub fn attr_name(attr: &Attribute) -> Option<String> {
    first_ident(attr.syntax()).map(|t| t.text().to_owned())
}

/// Returns all `Path` segments (`a::b::c`) joined by `"::"`.
pub fn path_text(path: &Path) -> String {
    path.syntax()
        .children_with_tokens()
        .filter_map(|el| el.into_token())
        .filter(|tok| !tok.kind().is_trivia())
        .map(|tok| tok.text().to_owned())
        .collect::<Vec<_>>()
        .join("")
}

/// Returns `true` if `kind` represents a CST type node.
#[inline]
pub const fn is_type_node(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::TypeRef
            | SyntaxKind::ArrayType
            | SyntaxKind::RefType
            | SyntaxKind::PtrTermType
            | SyntaxKind::TupleType
    )
}

/// Returns `true` if `kind` represents a CST expression node.
#[inline]
pub const fn is_expr_node(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::IfExpr
            | SyntaxKind::MatchExpr
            | SyntaxKind::ForExpr
            | SyntaxKind::BinaryExpr
            | SyntaxKind::PrefixExpr
            | SyntaxKind::CastExpr
            | SyntaxKind::PostfixCallExpr
            | SyntaxKind::FieldExpr
            | SyntaxKind::IndexExpr
            | SyntaxKind::StructLitExpr
            | SyntaxKind::BundleLitExpr
            | SyntaxKind::RecordLitExpr
            | SyntaxKind::ArrayLitExpr
            | SyntaxKind::TupleExpr
            | SyntaxKind::ParenExpr
            | SyntaxKind::PathExpr
            | SyntaxKind::LiteralExpr
            | SyntaxKind::SpawnExpr
            | SyntaxKind::SpawnBatchExpr
            | SyntaxKind::DespawnAllExpr
            | SyntaxKind::InsertExpr
            | SyntaxKind::RemoveExpr
    )
}

/// Strips surrounding quotes from a string literal token and unescapes standard escape sequences.
pub fn unquote_string_lit(raw: &str) -> String {
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') | None => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Returns `true` if `node` carries an attribute with identifier `name`.
pub fn has_attr(node: &SyntaxNode, name: &str) -> bool {
    attrs(node)
        .iter()
        .any(|a| attr_name(a).as_deref() == Some(name))
}

/// Extracts the visual group name from `@node_group("...")` or `@node_group(name = "...")`.
pub fn node_group(node: &SyntaxNode) -> Option<String> {
    attrs(node)
        .into_iter()
        .find(|a| attr_name(a).as_deref() == Some("node_group"))
        .and_then(|a| a.first_string_arg())
}

fn first_expr_after_token(node: &SyntaxNode, sep: SyntaxKind) -> Option<SyntaxNode> {
    let mut seen_sep = false;
    for el in node.children_with_tokens() {
        match el {
            NodeOrToken::Token(tok) if tok.kind() == sep => {
                seen_sep = true;
            }
            NodeOrToken::Node(child) if seen_sep && is_expr_node(child.kind()) => {
                return Some(child);
            }
            _ => {}
        }
    }
    None
}

fn first_block_after_token(node: &SyntaxNode, kw: SyntaxKind) -> Option<Block> {
    let mut seen_kw = false;
    for el in node.children_with_tokens() {
        match el {
            NodeOrToken::Token(tok) if tok.kind() == kw => {
                seen_kw = true;
            }
            NodeOrToken::Node(child) if seen_kw => {
                if let Some(block) = Block::cast(child) {
                    return Some(block);
                }
            }
            _ => {}
        }
    }
    None
}

impl SourceFile {
    /// Iterates all top-level [`Item`]s in declaration order.
    pub fn items(&self) -> impl Iterator<Item = Item> {
        self.syntax().children().filter_map(Item::cast)
    }

    /// Returns the `module ...;` header if present.
    pub fn module_decl(&self) -> Option<ModuleDecl> {
        child(self.syntax())
    }
}

impl ModuleDecl {
    /// Returns the declared module path (`a::b`).
    pub fn path(&self) -> Option<Path> {
        child(self.syntax())
    }

    /// Returns all attached attributes (`@version(...)`, `@deterministic`, etc.).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }
}

impl ComponentDecl {
    /// Returns the component name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@soa`, `@summary_tick`, `@persist`, `@sparse`, `@rollback`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns `@require(...)` clause if present.
    pub fn require_clause(&self) -> Option<RequireClause> {
        child(self.syntax())
    }

    /// Returns all `@require(...)` clauses attached to this component.
    pub fn require_clauses(&self) -> Vec<RequireClause> {
        children(self.syntax()).collect()
    }

    /// Returns `true` if this component uses `@soa` or declares any stratum blocks.
    pub fn is_soa(&self) -> bool {
        has_attr(self.syntax(), "soa") || !self.strata().is_empty()
    }

    /// Returns `true` if this component is a semicolon-terminated unit marker (`component Marker;`).
    pub fn is_unit_marker(&self) -> bool {
        let mut has_semi = false;
        let mut has_lbrace = false;
        for el in self.syntax().children_with_tokens() {
            if let Some(tok) = el.into_token() {
                if tok.kind() == SyntaxKind::Semi {
                    has_semi = true;
                } else if tok.kind() == SyntaxKind::LBrace {
                    has_lbrace = true;
                }
            }
        }
        has_semi && !has_lbrace
    }

    /// Returns `@soa` strata (`hot` / `cold <name>`) if present.
    pub fn strata(&self) -> Vec<StratumBlock> {
        children(self.syntax()).collect()
    }

    /// Returns direct fields (non-`@soa` components).
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }

    /// Returns all fields, flattening across `strata()` if SoA or returning direct `fields()`.
    pub fn all_fields(&self) -> Vec<FieldDecl> {
        let strata = self.strata();
        if strata.is_empty() {
            self.fields()
        } else {
            strata.into_iter().flat_map(|s| s.fields()).collect()
        }
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl StratumBlock {
    /// Returns `true` if this is the `hot { ... }` stratum.
    pub fn is_hot(&self) -> bool {
        self.syntax()
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .any(|tok| tok.kind() == SyntaxKind::KwHot)
    }

    /// Returns the cold stratum suffix name (or `"hot"` for the hot stratum).
    pub fn stratum_name(&self) -> String {
        if self.is_hot() {
            "hot".to_owned()
        } else {
            first_ident(self.syntax())
                .map(|t| t.text().to_owned())
                .unwrap_or_else(|| "cold".to_owned())
        }
    }

    /// Returns the cold stratum identifier token (or `None` for the `hot` stratum).
    pub fn name_token(&self) -> Option<SyntaxToken> {
        if self.is_hot() {
            None
        } else {
            first_ident(self.syntax())
        }
    }

    /// Returns all field declarations in this stratum.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }
}

impl FieldDecl {
    /// Returns attached field attributes (such as `@quantize(...)`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the field's identifier token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the type syntax node (may be `TypeRef`, `ArrayType`, `RefType`, etc.).
    pub fn type_node(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| is_type_node(n.kind()))
    }

    /// Returns the default value expression after `=` if present.
    pub fn default_expr(&self) -> Option<SyntaxNode> {
        first_expr_after_token(self.syntax(), SyntaxKind::Eq)
    }
}

impl StructDecl {
    /// Returns the struct name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns all field declarations.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }
}

impl EnumDecl {
    /// Returns the enum name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns all enum variants.
    pub fn variants(&self) -> Vec<VariantDecl> {
        children(self.syntax()).collect()
    }
}

impl ResourceDecl {
    /// Returns the resource name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@persist`, `@rollback`, `@net`, `@authority`, etc.).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns `@require(...)` clauses attached to this resource.
    pub fn require_clauses(&self) -> Vec<RequireClause> {
        children(self.syntax()).collect()
    }

    /// Returns all field declarations.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }
}

impl SysDecl {
    /// Returns the system name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@par(...)`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns parameter list.
    pub fn param_list(&self) -> Option<SysParamList> {
        child(self.syntax())
    }

    /// Returns `effects(...)` clause if present.
    pub fn effects(&self) -> Option<EffectsClause> {
        child(self.syntax())
    }

    /// Returns the body block.
    pub fn body(&self) -> Option<Block> {
        child(self.syntax())
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl ObsDecl {
    /// Returns the observer name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@par(...)`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns parameter list.
    pub fn param_list(&self) -> Option<SysParamList> {
        child(self.syntax())
    }

    /// Returns `effects(...)` clause if present.
    pub fn effects(&self) -> Option<EffectsClause> {
        child(self.syntax())
    }

    /// Returns the body block.
    pub fn body(&self) -> Option<Block> {
        child(self.syntax())
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl Attribute {
    /// Returns the attribute identifier token (e.g. `node_pure`, `net_rpc`).
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the attribute identifier name as a `String`.
    pub fn name_text(&self) -> Option<String> {
        attr_name(self)
    }

    /// Returns the parenthesized argument list if present.
    pub fn arg_list(&self) -> Option<AttrArgList> {
        child(self.syntax())
    }

    /// Returns all attribute arguments.
    pub fn args(&self) -> Vec<AttrArg> {
        self.arg_list().map(|l| l.args()).unwrap_or_default()
    }

    /// Extracts an unquoted string argument from either `@attr("val")` or `@attr(name = "val")`.
    pub fn first_string_arg(&self) -> Option<String> {
        let arg = self.args().into_iter().next()?;
        if let Some(key) = arg.key()
            && key.text() != "name"
        {
            return None;
        }
        let expr = arg.value_expr()?;
        if expr.kind() != SyntaxKind::LiteralExpr {
            return None;
        }
        let str_tok = expr
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .find(|tok| tok.kind() == SyntaxKind::StringLit)?;
        Some(unquote_string_lit(str_tok.text()))
    }
}

impl AttrArgList {
    /// Returns all attribute arguments inside `(...)`.
    pub fn args(&self) -> Vec<AttrArg> {
        children(self.syntax()).collect()
    }
}

impl AttrArg {
    /// Returns the argument key identifier if this is a `key = value` argument.
    pub fn key(&self) -> Option<SyntaxToken> {
        let has_eq = self
            .syntax()
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .any(|tok| tok.kind() == SyntaxKind::Eq);
        if has_eq {
            first_ident(self.syntax())
        } else {
            None
        }
    }

    /// Returns the semantic version node if this argument is a `SemVer` (`1.0.0`).
    pub fn semver(&self) -> Option<SemVer> {
        child(self.syntax())
    }

    /// Returns the value expression node if present.
    pub fn value_expr(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|c| is_expr_node(c.kind()))
    }

    /// Returns the trimmed value text (after `=` if keyed, otherwise full trimmed argument text).
    pub fn value_text(&self) -> String {
        if let Some(expr) = self.value_expr() {
            return expr.text().to_string().trim().to_owned();
        }
        if let Some(sv) = self.semver() {
            return sv.syntax().text().to_string().trim().to_owned();
        }
        let raw = self.syntax().text().to_string();
        if self.key().is_some()
            && let Some((_, rhs)) = raw.split_once('=')
        {
            return rhs.trim().to_owned();
        }
        raw.trim().to_owned()
    }
}

impl GenericParams {
    /// Returns all generic parameter name tokens.
    pub fn param_names(&self) -> Vec<SyntaxToken> {
        self.syntax()
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .filter(|tok| tok.kind() == SyntaxKind::Ident)
            .collect()
    }

    /// Returns each generic parameter name paired with its optional `: Bound` type node.
    pub fn params(&self) -> Vec<(SyntaxToken, Option<SyntaxNode>)> {
        let mut result = Vec::new();
        let mut current_name: Option<SyntaxToken> = None;
        let mut expect_bound = false;
        let mut current_bound: Option<SyntaxNode> = None;
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) => match tok.kind() {
                    SyntaxKind::Ident => {
                        if let Some(name) = current_name.take() {
                            result.push((name, current_bound.take()));
                        }
                        current_name = Some(tok);
                        expect_bound = false;
                    }
                    SyntaxKind::Colon => {
                        expect_bound = true;
                    }
                    SyntaxKind::Comma | SyntaxKind::Gt => {
                        if let Some(name) = current_name.take() {
                            result.push((name, current_bound.take()));
                        }
                        expect_bound = false;
                    }
                    _ => {}
                },
                NodeOrToken::Node(node) if expect_bound && is_type_node(node.kind()) => {
                    current_bound = Some(node);
                    expect_bound = false;
                }
                _ => {}
            }
        }
        if let Some(name) = current_name {
            result.push((name, current_bound));
        }
        result
    }
}

impl ParamList {
    /// Returns all parameter declarations.
    pub fn params(&self) -> Vec<Param> {
        children(self.syntax()).collect()
    }
}

impl Param {
    /// Returns the parameter name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the parameter type node.
    pub fn type_node(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| is_type_node(n.kind()))
    }

    /// Returns the optional default value expression after `=`.
    pub fn default_expr(&self) -> Option<SyntaxNode> {
        first_expr_after_token(self.syntax(), SyntaxKind::Eq)
    }
}

impl SysParamList {
    /// Returns all system/FSM/task `using` parameters.
    pub fn params(&self) -> Vec<SysParam> {
        children(self.syntax()).collect()
    }
}

impl SysParam {
    /// Returns the parameter name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the parameter type node.
    pub fn type_node(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| is_type_node(n.kind()))
    }
}

impl ProjTermList {
    /// Returns all query projection terms.
    pub fn terms(&self) -> Vec<ProjTerm> {
        children(self.syntax()).collect()
    }
}

impl ProjTerm {
    /// Returns the projection alias (`alias: &T`) if an explicit `:` alias is present.
    pub fn alias(&self) -> Option<SyntaxToken> {
        let has_colon = self
            .syntax()
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .any(|tok| tok.kind() == SyntaxKind::Colon);
        if has_colon {
            first_ident(self.syntax())
        } else {
            None
        }
    }

    /// Returns the projected term type node.
    pub fn type_node(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| is_type_node(n.kind()))
    }
}

impl RequireClause {
    /// Returns all required component/condition entries inside `@require(...)`.
    pub fn items(&self) -> Vec<RequireItem> {
        children(self.syntax()).collect()
    }
}

impl RequireItem {
    /// Returns the required component or field path.
    pub fn path(&self) -> Option<Path> {
        child(self.syntax())
    }

    /// Returns the optional required value expression after `=`.
    pub fn value_expr(&self) -> Option<SyntaxNode> {
        first_expr_after_token(self.syntax(), SyntaxKind::Eq)
    }
}

impl FieldInitList {
    /// Returns all field initializer entries.
    pub fn inits(&self) -> Vec<FieldInit> {
        children(self.syntax()).collect()
    }
}

impl FieldInit {
    /// Returns the initialized field name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the initializer value expression if present (absent for shorthand `field`).
    pub fn value_expr(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| is_expr_node(n.kind()))
    }
}

impl RpcDecl {
    /// Returns the RPC declaration name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@net_rpc(...)`, `@authority(...)`, `@node_group(...)`, etc.).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns `@require(...)` clauses if present.
    pub fn require_clauses(&self) -> Vec<RequireClause> {
        children(self.syntax()).collect()
    }

    /// Returns all payload field declarations.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }

    /// Returns `true` if this RPC is a semicolon-terminated marker (`rpc Ping;`).
    pub fn is_marker(&self) -> bool {
        let mut has_semi = false;
        let mut has_lbrace = false;
        for el in self.syntax().children_with_tokens() {
            if let Some(tok) = el.into_token() {
                if tok.kind() == SyntaxKind::Semi {
                    has_semi = true;
                } else if tok.kind() == SyntaxKind::LBrace {
                    has_lbrace = true;
                }
            }
        }
        has_semi && !has_lbrace
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl NetSimTestDecl {
    /// Returns the raw `StringLit` test name token.
    pub fn name_token(&self) -> Option<SyntaxToken> {
        self.syntax()
            .children_with_tokens()
            .filter_map(|el| el.into_token())
            .find(|tok| tok.kind() == SyntaxKind::StringLit)
    }

    /// Returns the unquoted test name string.
    pub fn name(&self) -> Option<String> {
        self.name_token().map(|t| unquote_string_lit(t.text()))
    }

    /// Returns attached attributes.
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the parenthesized `(latency: ..., jitter: ..., ...)` parameter list if present.
    pub fn param_list(&self) -> Option<NetSimParamList> {
        child(self.syntax())
    }

    /// Returns all network simulation parameters.
    pub fn params(&self) -> Vec<NetSimParam> {
        self.param_list().map(|l| l.params()).unwrap_or_default()
    }

    /// Returns the simulation test body block.
    pub fn body(&self) -> Option<Block> {
        child(self.syntax())
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl NetSimParamList {
    /// Returns all `key: value` parameter entries inside `(...)`.
    pub fn params(&self) -> Vec<NetSimParam> {
        children(self.syntax()).collect()
    }
}

impl NetSimParam {
    /// Returns the parameter key identifier token (e.g. `latency`, `jitter`, `loss`, `seed`).
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the parameter value expression node.
    pub fn value_expr(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|c| is_expr_node(c.kind()))
    }

    /// Returns the trimmed parameter value text.
    pub fn value_text(&self) -> Option<String> {
        if let Some(expr) = self.value_expr() {
            return Some(expr.text().to_string().trim().to_owned());
        }
        let raw = self.syntax().text().to_string();
        let (_, rhs) = raw.split_once(':')?;
        let trimmed = rhs.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }
}

impl FnDecl {
    /// Returns the function name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (e.g. `@node_pure`, `@node_group(...)`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns generic type parameters if present.
    pub fn generic_params(&self) -> Option<GenericParams> {
        child(self.syntax())
    }

    /// Returns the parameter list node.
    pub fn param_list(&self) -> Option<ParamList> {
        child(self.syntax())
    }

    /// Returns all function parameters.
    pub fn params(&self) -> Vec<Param> {
        self.param_list().map(|p| p.params()).unwrap_or_default()
    }

    /// Returns the return type syntax node after `->` if present.
    pub fn return_type(&self) -> Option<SyntaxNode> {
        let mut seen_arrow = false;
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::ThinArrow => {
                    seen_arrow = true;
                }
                NodeOrToken::Node(node) if seen_arrow && is_type_node(node.kind()) => {
                    return Some(node);
                }
                _ => {}
            }
        }
        None
    }

    /// Returns the function body block.
    pub fn body(&self) -> Option<Block> {
        child(self.syntax())
    }

    /// Returns `true` if the function carries `@node_pure`.
    pub fn is_node_pure(&self) -> bool {
        has_attr(self.syntax(), "node_pure")
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl TimelineDecl {
    /// Returns the timeline name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@rate(...)`, `@duration(...)`, `@sparse`, `@node_group(...)`).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns `@require(...)` clauses if present.
    pub fn require_clauses(&self) -> Vec<RequireClause> {
        children(self.syntax()).collect()
    }

    /// Returns all `window name = range;` entries.
    pub fn windows(&self) -> Vec<TimelineWindow> {
        children(self.syntax()).collect()
    }

    /// Returns all `at frame => stmt` entries.
    pub fn at_entries(&self) -> Vec<TimelineAt> {
        children(self.syntax()).collect()
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl TimelineWindow {
    /// Returns the window identifier token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the window range expression (`0_f .. 4_f`).
    pub fn range_expr(&self) -> Option<SyntaxNode> {
        first_expr_after_token(self.syntax(), SyntaxKind::Eq)
            .or_else(|| self.syntax().children().find(|c| is_expr_node(c.kind())))
    }
}

impl TimelineAt {
    /// Returns the trigger time/frame expression before `=>`.
    pub fn time_expr(&self) -> Option<SyntaxNode> {
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::FatArrow => break,
                NodeOrToken::Node(node) if is_expr_node(node.kind()) => return Some(node),
                _ => {}
            }
        }
        None
    }

    /// Returns the action statement or block node after `=>`.
    pub fn action_node(&self) -> Option<SyntaxNode> {
        let mut seen_arrow = false;
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::FatArrow => {
                    seen_arrow = true;
                }
                NodeOrToken::Node(node) if seen_arrow => return Some(node),
                _ => {}
            }
        }
        None
    }
}

impl FsmDecl {
    /// Returns the FSM name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@persist`, `@node_group(...)`, etc.).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns optional FSM system parameters (`fsm Name(cal: &res Clock)`).
    pub fn param_list(&self) -> Option<SysParamList> {
        child(self.syntax())
    }

    /// Returns all FSM system parameters.
    pub fn params(&self) -> Vec<SysParam> {
        self.param_list().map(|p| p.params()).unwrap_or_default()
    }

    /// Returns `@require(...)` clauses if present.
    pub fn require_clauses(&self) -> Vec<RequireClause> {
        children(self.syntax()).collect()
    }

    /// Returns the initial state identifier token from `initial State ...;`.
    pub fn initial_state(&self) -> Option<SyntaxToken> {
        let mut seen_initial = false;
        for el in self.syntax().children_with_tokens() {
            if let Some(tok) = el.into_token() {
                if tok.kind() == SyntaxKind::KwInitial {
                    seen_initial = true;
                } else if seen_initial && tok.kind() == SyntaxKind::Ident {
                    return Some(tok);
                } else if seen_initial && tok.kind() == SyntaxKind::Semi {
                    break;
                }
            }
        }
        None
    }

    /// Returns the optional `RecordLitExpr` initializer on `initial State { ... };`.
    pub fn initial_args(&self) -> Option<SyntaxNode> {
        let mut seen_initial = false;
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::KwInitial => {
                    seen_initial = true;
                }
                NodeOrToken::Token(tok) if seen_initial && tok.kind() == SyntaxKind::Semi => {
                    break;
                }
                NodeOrToken::Node(node)
                    if seen_initial && node.kind() == SyntaxKind::RecordLitExpr =>
                {
                    return Some(node);
                }
                _ => {}
            }
        }
        None
    }

    /// Returns all `state Name { ... }` declarations.
    pub fn states(&self) -> Vec<StateDecl> {
        children(self.syntax()).collect()
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl StateDecl {
    /// Returns the state name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns all state-local field declarations.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }

    /// Returns the `on_enter { ... }` hook block if present.
    pub fn on_enter(&self) -> Option<Block> {
        first_block_after_token(self.syntax(), SyntaxKind::KwOnEnter)
    }

    /// Returns the `on_tick { ... }` hook block if present.
    pub fn on_tick(&self) -> Option<Block> {
        first_block_after_token(self.syntax(), SyntaxKind::KwOnTick)
    }

    /// Returns the `on_exit { ... }` hook block if present.
    pub fn on_exit(&self) -> Option<Block> {
        first_block_after_token(self.syntax(), SyntaxKind::KwOnExit)
    }

    /// Returns all `to Target ... when cond;` transition declarations.
    pub fn transitions(&self) -> Vec<TransitionDecl> {
        children(self.syntax()).collect()
    }
}

impl TransitionDecl {
    /// Returns the target state identifier token.
    pub fn target_state(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the optional `RecordLitExpr` payload initializer (`to State { ... } when ...`).
    pub fn target_args(&self) -> Option<SyntaxNode> {
        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) if tok.kind() == SyntaxKind::KwWhen => break,
                NodeOrToken::Node(node) if node.kind() == SyntaxKind::RecordLitExpr => {
                    return Some(node);
                }
                _ => {}
            }
        }
        None
    }

    /// Returns the transition guard expression after `when`.
    pub fn guard(&self) -> Option<SyntaxNode> {
        if let Some(expr) = first_expr_after_token(self.syntax(), SyntaxKind::KwWhen) {
            return Some(expr);
        }
        let target_range = self.target_args().map(|n| n.text_range());
        self.syntax()
            .children()
            .find(|n| is_expr_node(n.kind()) && Some(n.text_range()) != target_range)
    }

    /// Returns attributes attached to the transition.
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }
}

/// A `.filter<Args>(args)` modifier chained after `on (...)` on a [`TaskDecl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFilterClause {
    /// Filter method name token (e.g. `with`, `without`).
    pub name: SyntaxToken,
    /// Optional generic arguments (`<T>`).
    pub generic_args: Option<GenericArgs>,
    /// Optional call argument list (`(...)`).
    pub arg_list: Option<ArgList>,
}

impl TaskDecl {
    /// Returns the task name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes (`@sparse`, `@node_group(...)`, etc.).
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the task input parameter list.
    pub fn param_list(&self) -> Option<ParamList> {
        child(self.syntax())
    }

    /// Returns all task input parameters.
    pub fn params(&self) -> Vec<Param> {
        self.param_list().map(|p| p.params()).unwrap_or_default()
    }

    /// Returns the `on (...)` projection term list if present.
    pub fn on_proj_list(&self) -> Option<ProjTermList> {
        child(self.syntax())
    }

    /// Returns all projection terms in the `on (...)` clause.
    pub fn on_terms(&self) -> Vec<ProjTerm> {
        self.on_proj_list().map(|l| l.terms()).unwrap_or_default()
    }

    /// Returns `.filter<Args>(args)` chain clauses between `on (...)` and `using (...)` / `{ ... }`.
    pub fn on_chain_filters(&self) -> Vec<TaskFilterClause> {
        let mut clauses = Vec::new();
        let mut active: Option<TaskFilterClause> = None;
        let mut after_dot = false;

        for el in self.syntax().children_with_tokens() {
            match el {
                NodeOrToken::Token(tok) => match tok.kind() {
                    SyntaxKind::KwUsing => break,
                    SyntaxKind::Dot => {
                        if let Some(prev) = active.take() {
                            clauses.push(prev);
                        }
                        after_dot = true;
                    }
                    SyntaxKind::Ident if after_dot => {
                        active = Some(TaskFilterClause {
                            name: tok,
                            generic_args: None,
                            arg_list: None,
                        });
                        after_dot = false;
                    }
                    k if !k.is_trivia() => {
                        after_dot = false;
                    }
                    _ => {}
                },
                NodeOrToken::Node(node) => {
                    if node.kind() == SyntaxKind::Block {
                        break;
                    }
                    if let Some(cur) = active.as_mut() {
                        if let Some(ga) = GenericArgs::cast(node.clone()) {
                            cur.generic_args = Some(ga);
                        } else if let Some(al) = ArgList::cast(node) {
                            cur.arg_list = Some(al);
                        }
                    }
                }
            }
        }
        if let Some(last) = active {
            clauses.push(last);
        }
        clauses
    }

    /// Returns the `using (...)` system parameter list if present.
    pub fn using_param_list(&self) -> Option<SysParamList> {
        child(self.syntax())
    }

    /// Returns all `using (...)` parameters.
    pub fn using_params(&self) -> Vec<SysParam> {
        self.using_param_list()
            .map(|l| l.params())
            .unwrap_or_default()
    }

    /// Returns the task body block.
    pub fn body(&self) -> Option<Block> {
        child(self.syntax())
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl TableDecl {
    /// Returns the table name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes.
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the key enum path after `by`.
    pub fn key_enum(&self) -> Option<Path> {
        child(self.syntax())
    }

    /// Returns all schema column field declarations.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }

    /// Returns all table data rows.
    pub fn rows(&self) -> Vec<TableRow> {
        children(self.syntax()).collect()
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl TableRow {
    /// Returns the enum variant identifier token for this row.
    pub fn variant_name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the `{ field: value, ... }` initializer list for this row.
    pub fn field_init_list(&self) -> Option<FieldInitList> {
        child(self.syntax())
    }

    /// Returns all field initializers in this row.
    pub fn inits(&self) -> Vec<FieldInit> {
        self.field_init_list()
            .map(|l| l.inits())
            .unwrap_or_default()
    }
}

impl CurveDecl {
    /// Returns the curve name token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns attached attributes.
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the domain/input type node before `->`.
    pub fn input_type(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|c| is_type_node(c.kind()))
    }

    /// Returns the range/output type node after `->`.
    pub fn output_type(&self) -> Option<SyntaxNode> {
        self.syntax()
            .children()
            .filter(|c| is_type_node(c.kind()))
            .nth(1)
    }

    /// Returns all `(x, y)` control points.
    pub fn points(&self) -> Vec<CurvePoint> {
        children(self.syntax()).collect()
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl CurvePoint {
    /// Returns the X coordinate expression.
    pub fn x_expr(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|c| is_expr_node(c.kind()))
    }

    /// Returns the Y coordinate expression.
    pub fn y_expr(&self) -> Option<SyntaxNode> {
        self.syntax()
            .children()
            .filter(|c| is_expr_node(c.kind()))
            .nth(1)
    }
}

/// Modifier kind on a [`ScheduleDecl`] or [`ScheduleNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScheduleModKind {
    /// Conditional execution predicate (`run_if(expr)`).
    RunIf,
    /// Ordering constraint (`before(path)`).
    Before,
    /// Ordering constraint (`after(path)`).
    After,
}

/// Structural kind of a [`ScheduleNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScheduleNodeKind {
    /// Strict sequential group (`seq Name { ... }`).
    Seq,
    /// Weak sequential group (`seq_weak Name { ... }`).
    SeqWeak,
    /// Parallel group (`par Name { ... }`).
    Par,
    /// Named system/task set (`set Name { ... }`).
    Set,
    /// Leaf scheduled item (`Path`).
    Leaf,
}

impl ScheduleDecl {
    /// Returns attached attributes.
    pub fn attributes(&self) -> Vec<Attribute> {
        attrs(self.syntax())
    }

    /// Returns the schedule label path (e.g. `FixedUpdate`, `Update`).
    pub fn label(&self) -> Option<Path> {
        child(self.syntax())
    }

    /// Returns the schedule label path joined as text.
    pub fn label_text(&self) -> Option<String> {
        self.label().map(|p| path_text(&p))
    }

    /// Returns top-level schedule modifiers (`run_if`, `before`, `after`).
    pub fn modifiers(&self) -> Vec<ScheduleMod> {
        children(self.syntax()).collect()
    }

    /// Returns top-level child schedule nodes.
    pub fn nodes(&self) -> Vec<ScheduleNode> {
        children(self.syntax()).collect()
    }

    /// Returns the `@node_group(...)` label if present.
    pub fn node_group(&self) -> Option<String> {
        node_group(self.syntax())
    }
}

impl ScheduleMod {
    /// Returns the modifier kind (`RunIf`, `Before`, or `After`).
    pub fn kind(&self) -> Option<ScheduleModKind> {
        for el in self.syntax().children_with_tokens() {
            if let Some(tok) = el.into_token() {
                match tok.kind() {
                    SyntaxKind::KwRunIf => return Some(ScheduleModKind::RunIf),
                    SyntaxKind::KwBefore => return Some(ScheduleModKind::Before),
                    SyntaxKind::KwAfter => return Some(ScheduleModKind::After),
                    _ => {}
                }
            }
        }
        None
    }

    /// Returns the `run_if(...)` condition expression if this is a `RunIf` modifier.
    pub fn condition_expr(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|c| is_expr_node(c.kind()))
    }

    /// Returns the `before(...)` / `after(...)` target path if present.
    pub fn target_path(&self) -> Option<Path> {
        child(self.syntax())
    }
}

impl ScheduleNode {
    /// Returns the schedule node kind (`Seq`, `SeqWeak`, `Par`, `Set`, or `Leaf`).
    pub fn kind(&self) -> ScheduleNodeKind {
        for el in self.syntax().children_with_tokens() {
            if let Some(tok) = el.into_token() {
                match tok.kind() {
                    SyntaxKind::KwSeq => return ScheduleNodeKind::Seq,
                    SyntaxKind::KwSeqWeak => return ScheduleNodeKind::SeqWeak,
                    SyntaxKind::KwPar => return ScheduleNodeKind::Par,
                    SyntaxKind::KwSet => return ScheduleNodeKind::Set,
                    _ => {}
                }
            }
        }
        ScheduleNodeKind::Leaf
    }

    /// Returns `true` if this node is a leaf item rather than a group block.
    pub fn is_leaf(&self) -> bool {
        self.kind() == ScheduleNodeKind::Leaf
    }

    /// Returns the group name token for `seq`/`seq_weak`/`par`/`set` nodes, or `None` for leaves.
    pub fn name(&self) -> Option<SyntaxToken> {
        if self.is_leaf() {
            None
        } else {
            first_ident(self.syntax())
        }
    }

    /// Returns the target path for leaf nodes, or `None` for group blocks.
    pub fn path(&self) -> Option<Path> {
        if self.is_leaf() {
            child(self.syntax())
        } else {
            None
        }
    }

    /// Returns the human-readable label (path text for leaves, group name for groups).
    pub fn label_text(&self) -> Option<String> {
        if self.is_leaf() {
            self.path().map(|p| path_text(&p))
        } else {
            self.name().map(|t| t.text().to_owned())
        }
    }

    /// Returns modifiers attached directly to this schedule node.
    pub fn modifiers(&self) -> Vec<ScheduleMod> {
        children(self.syntax()).collect()
    }

    /// Returns nested child schedule nodes inside a group block.
    pub fn children(&self) -> Vec<ScheduleNode> {
        children(self.syntax()).collect()
    }
}
