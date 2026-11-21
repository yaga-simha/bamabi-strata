//! Typed `rowan` AST wrappers over the lossless Strata v2.0 CST.

use crate::syntax_kind::{SyntaxKind, SyntaxNode, SyntaxToken};
use rowan::TextRange;

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

    /// Returns `@soa` strata (`hot` / `cold <name>`) if present.
    pub fn strata(&self) -> Vec<StratumBlock> {
        children(self.syntax()).collect()
    }

    /// Returns direct fields (non-`@soa` components).
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
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

    /// Returns all field declarations in this stratum.
    pub fn fields(&self) -> Vec<FieldDecl> {
        children(self.syntax()).collect()
    }
}

impl FieldDecl {
    /// Returns the field's identifier token.
    pub fn name(&self) -> Option<SyntaxToken> {
        first_ident(self.syntax())
    }

    /// Returns the type syntax node (may be `TypeRef`, `ArrayType`, `RefType`, etc.).
    pub fn type_node(&self) -> Option<SyntaxNode> {
        self.syntax().children().find(|n| {
            matches!(
                n.kind(),
                SyntaxKind::TypeRef
                    | SyntaxKind::ArrayType
                    | SyntaxKind::RefType
                    | SyntaxKind::PtrTermType
                    | SyntaxKind::TupleType
            )
        })
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
}
