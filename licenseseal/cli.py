from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import (
    DEFAULT_EXCLUDE_DIRS,
    FileResult,
    InjectionConfig,
    audit_project,
    compare_projects,
    generate_keypair,
    inject_project,
    remove_project,
)

# Import new extension modules
from . import index as index_module
from . import embeddings as embeddings_module
from . import trust as trust_module
from . import git_integration as git_module
from . import lsp as lsp_module
from . import watermark as watermark_module
from . import enterprise as enterprise_module
from . import sbom as sbom_module
from . import legal_report as legal_report_module
from . import firehose as firehose_module
from . import redteam as redteam_module
from . import firehose_queue as firehose_queue_module
from . import honey_multilang as honey_multilang_module
from . import osint as osint_module
from . import build_integration as build_integration_module
from . import semantic_morph as semantic_morph_module
from . import graph_fingerprint as graph_fingerprint_module
from . import bot as bot_module
from . import llm_interceptor as llm_interceptor_module
from . import sca_check as sca_check_module


def print_results(results: list[FileResult], root: Path) -> None:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.action] = counts.get(result.action, 0) + 1

    print("LicenseSeal result")
    print("==================")
    for action in sorted(counts):
        print(f"{action}: {counts[action]}")

    print("\nDetails:")
    for result in results:
        try:
            rel = result.path.relative_to(root)
        except ValueError:
            rel = result.path
        suffix = f" — {result.reason}" if result.reason else ""
        print(f"  [{result.action}] {rel}{suffix}")


def print_github_annotations(root: Path, unmarked: list[Path], verification: list[FileResult]) -> None:
    for path in unmarked:
        rel = path.relative_to(root)
        print(f"::error file={rel}::Missing LicenseSeal AI license boundary")
    for result in verification:
        if result.action == "verify_failed":
            rel = result.path.relative_to(root)
            reason = result.reason or "signature verification failed"
            print(f"::error file={rel}::{reason}")


def cmd_inject(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2

    if not getattr(args, "skip_sca", False):
        report = sca_check_module.check_project(root, args.license)
        blocking = [c for c in report.conflicts if c.severity == "error"]
        warnings = [c for c in report.conflicts if c.severity == "warning"]
        for c in warnings + blocking:
            print(f"SCA {c.severity.upper()}: {c.message}", file=sys.stderr)
        if blocking and not getattr(args, "force", False):
            print("ERROR: SCA license conflict detected. Use --force to proceed or --skip-sca to bypass.", file=sys.stderr)
            return 2

    cfg = InjectionConfig(
        root=root,
        license_id=args.license,
        owner=args.owner,
        project=args.project or root.name,
        dry_run=args.dry_run,
        backup=args.backup,
        write_policy=args.write_policy,
        include_configs=args.include_configs,
        update=args.update,
        private_key=Path(args.sign_key).resolve() if args.sign_key else None,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
        include_git=args.include_git if hasattr(args, 'include_git') else False,
    )
    try:
        results = inject_project(cfg)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print_results(results, root)
    return 1 if any(r.action == "error" for r in results) else 0


def cmd_remove(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2
    results = remove_project(
        root,
        include_configs=args.include_configs,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
        dry_run=args.dry_run,
        backup=args.backup,
    )
    print_results(results, root)
    return 1 if any(r.action == "error" for r in results) else 0


def cmd_audit(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        total, marked, unmarked, verification = audit_project(
            root,
            include_configs=args.include_configs,
            exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
            verify_key=Path(args.verify_key).resolve() if args.verify_key else None,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.format == "github":
        print_github_annotations(root, unmarked, verification)
    else:
        print(f"Audit root: {root}")
        print(f"Code/config files scanned: {total}")
        print(f"Files with AI license boundary: {marked}")
        print(f"Files missing boundary: {len(unmarked)}")
        if args.verify_key:
            ok = sum(1 for r in verification if r.action == "verified")
            failed = sum(1 for r in verification if r.action == "verify_failed")
            print(f"Signature verified: {ok}")
            print(f"Signature failed: {failed}")

        if unmarked:
            print("\nMissing boundary:")
            for path in unmarked[:200]:
                print(f"  - {path.relative_to(root)}")
            if len(unmarked) > 200:
                print(f"  ... and {len(unmarked) - 200} more")

        failed_verifications = [r for r in verification if r.action == "verify_failed"]
        if failed_verifications:
            print("\nSignature verification failures:")
            for result in failed_verifications[:200]:
                print(f"  - {result.path.relative_to(root)} {result.reason}")

    if unmarked or any(r.action == "verify_failed" for r in verification):
        return 1
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    original = Path(args.original).resolve()
    suspected = Path(args.suspected).resolve()

    if not original.is_dir():
        print(f"ERROR: original is not a directory: {original}", file=sys.stderr)
        return 2
    if not suspected.is_dir():
        print(f"ERROR: suspected is not a directory: {suspected}", file=sys.stderr)
        return 2

    report = compare_projects(
        original,
        suspected,
        include_configs=args.include_configs,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
    )

    output = json.dumps(report, indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    if report["structural_similarity"] >= args.threshold and "missing" in str(report["license_status"]):
        return 1
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.private_key).resolve()
    public_path = Path(args.public_key).resolve()
    try:
        results = generate_keypair(private_path, public_path, overwrite=args.overwrite)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print_results(results, private_path.parent)
    return 1 if any(r.action == "error" for r in results) else 0


def cmd_web(args: argparse.Namespace) -> int:
    from .web import find_free_port, serve

    port = args.port
    if args.auto_port:
        port = find_free_port(args.port, args.host)
    return serve(host=args.host, port=port, open_browser=args.open_browser)


# =============================================================================
# Extension 1: Local Signature Database (Index) Commands
# =============================================================================

def cmd_index(args: argparse.Namespace) -> int:
    """Index a project for fast similarity lookups."""
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2

    db_path = Path(args.db).resolve() if args.db else Path(".licenseseal/signatures.db")
    project_name = args.project or root.name

    cfg = index_module.IndexConfig(
        db_path=db_path,
        project_name=project_name,
        root=root,
        include_configs=args.include_configs,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
    )

    try:
        result = index_module.index_project(cfg)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Indexed project: {result['project']}")
    print(f"Root: {result['root']}")
    print(f"Files indexed: {result['file_count']}")
    print(f"Shingles stored: {result['shingle_count']}")
    print(f"Database: {db_path}")
    return 0


def cmd_compare_db(args: argparse.Namespace) -> int:
    """Compare a suspected project against indexed originals."""
    suspected = Path(args.suspected).resolve()
    if not suspected.is_dir():
        print(f"ERROR: suspected is not a directory: {suspected}", file=sys.stderr)
        return 2

    db_path = Path(args.db).resolve() if args.db else Path(".licenseseal/signatures.db")
    if not db_path.exists():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        print("Run 'licenseseal index' first to create an index.", file=sys.stderr)
        return 2

    try:
        result = index_module.compare_indexed(
            suspected_root=suspected,
            db_path=db_path,
            project_name=args.project,
            include_configs=args.include_configs,
            exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(result, indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    if result["structural_similarity"] >= args.threshold:
        return 1
    return 0


def cmd_index_list(args: argparse.Namespace) -> int:
    """List all indexed projects."""
    db_path = Path(args.db).resolve() if args.db else Path(".licenseseal/signatures.db")
    if not db_path.exists():
        print("No index database found.", file=sys.stderr)
        return 0

    projects = index_module.list_indexed_projects(db_path)
    if not projects:
        print("No projects indexed.")
        return 0

    print(f"Indexed projects in {db_path}:")
    print("=" * 60)
    for proj in projects:
        print(f"\nProject: {proj['name']}")
        print(f"  Root: {proj['root_path']}")
        print(f"  Indexed: {proj['indexed_at']}")
        print(f"  Files: {proj['file_count']}, Shingles: {proj['shingle_count']}")
    return 0


def cmd_index_remove(args: argparse.Namespace) -> int:
    """Remove a project from the index."""
    db_path = Path(args.db).resolve() if args.db else Path(".licenseseal/signatures.db")
    if not db_path.exists():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        return 2

    removed = index_module.remove_from_index(db_path, args.project)
    if removed:
        print(f"Removed project '{args.project}' from index.")
        return 0
    else:
        print(f"ERROR: project '{args.project}' not found in index.", file=sys.stderr)
        return 2


# =============================================================================
# Extension 2: Semantic Similarity (Embeddings) Commands
# =============================================================================

def cmd_semantic(args: argparse.Namespace) -> int:
    """Compare projects using semantic embeddings."""
    original = Path(args.original).resolve()
    suspected = Path(args.suspected).resolve()

    if not original.is_dir():
        print(f"ERROR: original is not a directory: {original}", file=sys.stderr)
        return 2
    if not suspected.is_dir():
        print(f"ERROR: suspected is not a directory: {suspected}", file=sys.stderr)
        return 2

    try:
        model = embeddings_module.get_embedding_model(
            model_name=args.model,
            device=args.device,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("\nInstall semantic search dependencies:", file=sys.stderr)
        print('  pip install "licenseseal[ai]"', file=sys.stderr)
        return 2

    result = embeddings_module.compare_semantic(
        original_root=original,
        suspected_root=suspected,
        model=model,
        include_configs=args.include_configs,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
        threshold=args.threshold,
    )

    output = json.dumps(result, indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    if result["semantic_similarity"] >= args.threshold:
        return 1
    return 0


# =============================================================================
# Extension 3: Decentralized Trust Infrastructure Commands
# =============================================================================

def cmd_trust_fetch(args: argparse.Namespace) -> int:
    """Fetch a public key from a domain using trust discovery."""
    domain = args.domain

    trust = trust_module.TrustDiscovery()
    key = trust.fetch_public_key(domain)

    if key:
        print(f"Public key for {domain}:")
        print(f"  Key ID: {key.key_id}")
        print(f"  Owner: {key.owner}")
        print(f"  Discovered via: {key.discovered_via}")
        print(f"  Discovered at: {key.discovered_at}")
        print(f"\nPublic Key PEM:")
        print(key.public_key_pem)
        return 0
    else:
        print(f"ERROR: No public key found for domain '{domain}'", file=sys.stderr)
        print("The domain may not have a LicenseSeal key configured.", file=sys.stderr)
        return 2


def cmd_trust_verify(args: argparse.Namespace) -> int:
    """Verify a public key is associated with a domain."""
    public_key_path = Path(args.public_key).resolve()
    domain = args.domain

    if not public_key_path.exists():
        print(f"ERROR: public key file not found: {public_key_path}", file=sys.stderr)
        return 2

    public_key_pem = public_key_path.read_text()

    verified = trust_module.verify_key_for_domain(public_key_pem, domain)
    if verified:
        print(f"✓ Public key is associated with {domain}")
        return 0
    else:
        print(f"✗ Public key is NOT associated with {domain}", file=sys.stderr)
        return 1


def cmd_trust_init(args: argparse.Namespace) -> int:
    """Initialize .well-known endpoint for a domain."""
    output_path = Path(args.output).resolve()
    key_id = args.key_id
    public_key_path = Path(args.public_key).resolve()

    if not public_key_path.exists():
        print(f"ERROR: public key file not found: {public_key_path}", file=sys.stderr)
        return 2

    public_key_pem = public_key_path.read_text()
    owner = args.owner or "LicenseSeal User"
    domains = args.domain or [output_path.parent.name + ".com"]

    trust_module.create_well_known_file(
        output_path=output_path,
        key_id=key_id,
        public_key_pem=public_key_pem,
        owner=owner,
        domains=domains,
    )

    print(f"Created .well-known file: {output_path}")
    print(f"\nTo publish, place the file at:")
    print(f"  https://{domains[0]}/.well-known/licenseseal-keys.json")
    return 0


# =============================================================================
# Extension 4: Git History Integration Commands
# =============================================================================

def cmd_git_info(args: argparse.Namespace) -> int:
    """Show Git commit information for a project."""
    root = Path(args.root).resolve()

    commit_info = git_module.get_git_info(root)
    if not commit_info:
        print(f"ERROR: not a git repository: {root}", file=sys.stderr)
        return 2

    print(f"Git Information for {root.name}")
    print("=" * 50)
    print(f"Commit: {commit_info.commit_hash}")
    print(f"Short:  {commit_info.short_hash}")
    print(f"Author: {commit_info.author}")
    print(f"Date:   {commit_info.committed_at}")
    print(f"Message: {commit_info.message}")
    print(f"Repo:   {commit_info.repository_url}")
    if commit_info.branch:
        print(f"Branch: {commit_info.branch}")
    return 0


def cmd_git_verify(args: argparse.Namespace) -> int:
    """Verify a commit hash exists in the repository."""
    root = Path(args.root).resolve()

    exists = git_module.verify_marker_commit(args.commit, root)
    if exists:
        print(f"✓ Commit {args.commit} exists in repository")
        return 0
    else:
        print(f"✗ Commit {args.commit} NOT found in repository", file=sys.stderr)
        return 1


def cmd_git_history(args: argparse.Namespace) -> int:
    """Show commit history for a project."""
    root = Path(args.root).resolve()

    git = git_module.GitHistory(root)
    commits = git.get_commit_history(max_count=args.max_count)

    if not commits:
        print(f"No commits found in {root}", file=sys.stderr)
        return 2

    print(f"Commit history for {root.name}")
    print("=" * 70)
    for commit in commits:
        print(f"{commit.short_hash} | {commit.committed_at[:10]} | {commit.message[:50]}")
        print(f"         | {commit.author}")
    return 0


# =============================================================================
# Extension 5: IDE Integration (LSP) Commands
# =============================================================================

def cmd_lsp(args: argparse.Namespace) -> int:
    """Start the LicenseSeal LSP server."""
    config = lsp_module.LSPConfig(
        host=args.host,
        port=args.port,
        log_file=Path(args.log) if args.log else None,
        strict_mode=args.strict,
        check_on_save=not args.no_check_on_save,
    )

    try:
        return lsp_module.run_lsp_server(config)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("\nInstall LSP dependencies:", file=sys.stderr)
        print('  pip install "licenseseal[lsp]"', file=sys.stderr)
        return 2


def cmd_lsp_check(args: argparse.Namespace) -> int:
    """Check a file for license compliance (LSP-style)."""
    file_path = Path(args.file).resolve()

    server = lsp_module.create_lsp_server()
    result = server.check_file(file_path)

    print(f"License check for {file_path}")
    print("=" * 50)
    print(f"Has marker: {result.has_marker}")
    print(f"Is valid:   {result.is_valid}")

    if result.license_id:
        print(f"License:   {result.license_id}")
    if result.owner:
        print(f"Owner:     {result.owner}")

    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  ✗ {error}")

    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"  ⚠ {warning}")

    return 0 if result.is_valid else 1


def cmd_lsp_validate(args: argparse.Namespace) -> int:
    """Validate license compatibility between two licenses."""
    source_license = args.source_license
    target_license = args.target_license

    server = lsp_module.create_lsp_server()
    compatible, reason = server.validate_license_compatibility(
        source_license, target_license
    )

    if compatible:
        print(f"✓ {source_license} is compatible with {target_license}")
        print(f"  {reason}")
        return 0
    else:
        print(f"✗ {source_license} is NOT compatible with {target_license}")
        print(f"  {reason}")
        return 1


# =============================================================================
# Extension 1b: Watermark Commands
# =============================================================================

def cmd_watermark_embed(args: argparse.Namespace) -> int:
    """Embed invisible watermark into project files."""
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2

    config = watermark_module.create_watermark_config(
        project_id=args.project_id,
        strength=args.strength,
    )

    from .core import iter_candidate_files
    files = list(iter_candidate_files(root, None, False))

    signature = args.signature or f"watermark_{args.project_id}"

    results = watermark_module.watermark_project_files(
        files=files,
        project_id=args.project_id,
        signature=signature,
        config=config,
    )

    success = sum(1 for v in results.values() if v)
    print(f"Watermarked {success} of {len(files)} files")
    return 0 if success > 0 else 1


def cmd_watermark_extract(args: argparse.Namespace) -> int:
    """Extract watermark from a file."""
    file_path = Path(args.file).resolve()
    if not file_path.exists():
        print(f"ERROR: file not found: {file_path}", file=sys.stderr)
        return 2

    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"ERROR: cannot read file: {e}", file=sys.stderr)
        return 2

    watermark = watermark_module.extract_watermark(source)
    if watermark:
        print(f"Watermark detected:")
        print(f"  Project ID: {watermark.get('project_id', 'unknown')}")
        print(f"  Method: {watermark.get('method', 'unknown')}")
        print(f"  Signature: {watermark.get('signature', 'N/A')}")
        return 0
    else:
        print("No watermark detected")
        return 1


def cmd_watermark_scan(args: argparse.Namespace) -> int:
    """Scan project for watermarks."""
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2

    from .core import iter_candidate_files
    files = list(iter_candidate_files(root, None, False))

    results = watermark_module.scan_for_watermarks(files)

    found = sum(1 for v in results.values() if v is not None)
    print(f"Scanned {len(files)} files")
    print(f"Watermarks found: {found}")

    for path, wm in results.items():
        if wm:
            print(f"  {path.relative_to(root)}: {wm.get('project_id', 'unknown')}")

    return 0


# =============================================================================
# Extension 2b: Enterprise Registry Commands
# =============================================================================

def cmd_registry_init(args: argparse.Namespace) -> int:
    """Initialize enterprise registry."""
    config = enterprise_module.RegistryConfig(
        database_url=args.database_url,
    )

    try:
        registry = enterprise_module.create_registry(config)
        registry.initialize_schema()
        print(f"Registry initialized at: {args.database_url}")
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("\nInstall enterprise dependencies:", file=sys.stderr)
        print('  pip install "licenseseal[enterprise]"', file=sys.stderr)
        return 2


def cmd_registry_register(args: argparse.Namespace) -> int:
    """Register project in enterprise registry."""
    root = Path(args.root).resolve()

    if args.remote:
        # Use remote registry
        client = enterprise_module.create_remote_client(args.remote, args.api_key)
        project_data = {
            "name": root.name,
            "root_path": str(root),
            "license_id": "UNKNOWN",
            "owner": "unknown",
        }
        if client.push_signature(project_data):
            print(f"Registered {root.name} in remote registry")
            return 0
        else:
            print(f"ERROR: failed to register in remote registry", file=sys.stderr)
            return 2
    else:
        # Use local PostgreSQL
        config = enterprise_module.RegistryConfig(
            database_url=args.database_url or "postgresql://localhost:5432/licenseseal",
        )
        try:
            registry = enterprise_module.create_registry(config)
            registry.initialize_schema()

            import hashlib
            from .core import project_signature
            from .watermark import expected_honey_logic_fingerprints

            sig = project_signature(root)
            signature = hashlib.sha256(
                json.dumps(sig, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()

            project = registry.register_project(
                name=root.name,
                owner=args.owner or "unknown",
                license_id=args.license_id or "UNKNOWN",
                root_path=root,
                signature=signature,
                shingle_hash=str(hash(tuple(sig.keys()))),
                repository_url=args.repository_url or "",
            )

            honey_count = 0
            if not args.no_honey:
                for fp in expected_honey_logic_fingerprints(
                    project_id=args.project_id or project.id,
                    signature=signature,
                    density=args.honey_density,
                ):
                    registry.register_honey_fingerprint(
                        project_id=project.id,
                        fingerprint=fp.fingerprint,
                        rarity_score=fp.rarity_score,
                        features={
                            "function": fp.function,
                            "constants": fp.constants,
                            "operators": fp.operators,
                            "shape": fp.shape,
                            "project_id": args.project_id or project.id,
                            "signature": signature,
                        },
                    )
                    honey_count += 1

            print(f"Registered {project.name} (ID: {project.id})")
            print(f"Signature: {signature[:24]}...")
            print(f"Honey-logic fingerprints: {honey_count}")
            return 0
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2


def cmd_registry_search(args: argparse.Namespace) -> int:
    """Search registry for similar projects."""
    if args.remote:
        client = enterprise_module.create_remote_client(args.remote, args.api_key)
        results = client.search_remote({"threshold": args.threshold})
    else:
        config = enterprise_module.RegistryConfig(
            database_url=args.database_url or "postgresql://localhost:5432/licenseseal",
        )
        try:
            registry = enterprise_module.create_registry(config)
            results = registry.find_similar_projects(
                embedding=[0.0] * 384,  # Would need actual embedding
                threshold=args.threshold,
            )
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    print(f"Found {len(results)} similar projects:")
    for r in results:
        print(f"  {r.get('name')}: {r.get('similarity', 0) * 100:.1f}%")

    return 0


def cmd_registry_list(args: argparse.Namespace) -> int:
    """List projects in registry."""
    config = enterprise_module.RegistryConfig(
        database_url=args.database_url or "postgresql://localhost:5432/licenseseal",
    )
    try:
        registry = enterprise_module.create_registry(config)
        projects = registry.list_projects()

        print(f"Registry contains {len(projects)} projects:")
        for p in projects:
            print(f"  {p.name} ({p.status.value})")

        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_firehose_scan(args: argparse.Namespace) -> int:
    """Scan one candidate repository/path and persist evidence in the registry."""
    config = enterprise_module.RegistryConfig(
        database_url=args.database_url or "postgresql://localhost:5432/licenseseal",
    )
    try:
        registry = enterprise_module.create_registry(config)
        registry.initialize_schema()
        scanner = firehose_module.FirehoseScanner(
            registry=registry,
            config=firehose_module.FirehoseConfig(
                workdir=Path(args.workdir).resolve(),
                min_score=args.threshold,
                clone_depth=args.clone_depth,
                include_configs=args.include_configs,
                max_files_per_repo=args.max_files,
                exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
            ),
        )
        candidate = firehose_module.candidate_from_string(args.candidate)
        summary = scanner.scan_candidate(candidate, record=not args.no_record)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: firehose scan failed: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(summary.to_dict(), indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    return 1 if any(score >= args.threshold for score in summary.scores.values()) else 0


# =============================================================================
# Extension 3b: Cross-Lingual Commands
# =============================================================================

def cmd_cross_lingual(args: argparse.Namespace) -> int:
    """Detect code translation across languages."""
    original = Path(args.original).resolve()
    suspected = Path(args.suspected).resolve()

    if not original.is_dir() or not suspected.is_dir():
        print("ERROR: both paths must be directories", file=sys.stderr)
        return 2

    try:
        model = embeddings_module.get_code_embedding_model(
            model_type=args.model,
            device=args.device,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print('\nInstall: pip install "licenseseal[ai]"', file=sys.stderr)
        return 2

    result = embeddings_module.compare_cross_lingual(
        original_root=original,
        suspected_root=suspected,
        model=model,
        threshold=args.threshold,
    )

    output = json.dumps(result, indent=2, ensure_ascii=False)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    if result.get("max_cross_lingual_similarity", 0) >= args.threshold:
        return 1
    return 0


# =============================================================================
# Extension 4b: SBOM Commands
# =============================================================================

def cmd_sbom_export(args: argparse.Namespace) -> int:
    """Export project as SBOM."""
    root = Path(args.root).resolve()

    output_path = Path(args.output) if args.output else None

    try:
        sbom = sbom_module.generate_sbom(
            root=root,
            project_name=root.name,
            output_path=output_path,
            format=args.format,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if output_path:
        print(f"SBOM exported to: {output_path}")
    else:
        print(sbom)

    return 0


def cmd_sbom_validate(args: argparse.Namespace) -> int:
    """Validate a SBOM file."""
    sbom_path = Path(args.file).resolve()

    if not sbom_path.exists():
        print(f"ERROR: file not found: {sbom_path}", file=sys.stderr)
        return 2

    valid, errors = sbom_module.validate_sbom(sbom_path)

    if valid:
        print(f"✓ SBOM is valid")
        return 0
    else:
        print(f"✗ SBOM validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1


# =============================================================================
# Extension 5b: Legal Report Commands
# =============================================================================

def cmd_report(args: argparse.Namespace) -> int:
    """Generate legal evidence report."""
    original = Path(args.original).resolve()
    suspected = Path(args.suspected).resolve()
    output = Path(args.output).resolve()

    if not original.is_dir() or not suspected.is_dir():
        print("ERROR: both paths must be directories", file=sys.stderr)
        return 2

    # Get similarity data
    from .core import compare_projects
    similarity = compare_projects(original, suspected)

    try:
        result = legal_report_module.generate_legal_report(
            original_root=original,
            suspected_root=suspected,
            similarity_data=similarity,
            output_path=output,
            format=args.format,
        )
        print(f"Report generated: {result}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_dmca(args: argparse.Namespace) -> int:
    """Generate DMCA takedown notice."""
    original = Path(args.original).resolve()
    suspected = args.suspected
    output = Path(args.output).resolve()

    try:
        result = legal_report_module.generate_dmca_notice(
            original_root=original,
            suspected_root=Path(suspected),
            output_path=output,
        )
        print(f"DMCA notice generated: {result}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_certificate(args: argparse.Namespace) -> int:
    """Generate compliance certificate."""
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()

    try:
        result = legal_report_module.generate_compliance_certificate(
            root=root,
            output_path=output,
        )
        print(f"Certificate generated: {result}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2



def cmd_firehose_enqueue(args: argparse.Namespace) -> int:
    """Enqueue a candidate for distributed Firehose scanning."""
    payload = firehose_queue_module.payload_from_candidate(
        args.candidate,
        database_url=args.database_url,
        workdir=args.workdir,
        min_score=args.threshold,
        clone_depth=args.clone_depth,
        max_files_per_repo=args.max_files,
        include_configs=args.include_configs,
        record=not args.no_record,
    )
    try:
        result = firehose_queue_module.enqueue_candidate(payload)
        print(json.dumps({"queued": True, "task_id": getattr(result, "id", None), "candidate": args.candidate}, indent=2))
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def cmd_firehose_worker(args: argparse.Namespace) -> int:
    """Print worker startup guidance for Celery-based Firehose workers."""
    if firehose_queue_module.Celery is None:
        print('ERROR: Celery is not installed. Install with: pip install "licenseseal[queue]"', file=sys.stderr)
        return 2
    print("Start a worker with:")
    print("  celery -A licenseseal.firehose_queue.celery_app worker --loglevel=INFO")
    print("Environment:")
    print("  LICENSESEAL_CELERY_BROKER, LICENSESEAL_CELERY_BACKEND, LICENSESEAL_DATABASE_URL")
    return 0


def cmd_stress_test(args: argparse.Namespace) -> int:
    """Run defensive watermark/Honey-Logic survival testing on own code."""
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"ERROR: root is not a directory: {root}", file=sys.stderr)
        return 2
    cfg = redteam_module.StressTestConfig(
        root=root,
        sample_size=args.sample_size,
        mode=args.mode,
        seed=args.seed,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        lmstudio_url=args.lmstudio_url,
        lmstudio_model=args.lmstudio_model,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
    )
    try:
        report = redteam_module.run_stress_test(cfg)
    except Exception as exc:
        print(f"ERROR: stress test failed: {exc}", file=sys.stderr)
        return 2
    payload = report.to_dict()
    output = json.dumps(payload, indent=2, ensure_ascii=False)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    return 1 if payload["overall_survival_rate"] < args.threshold else 0


def cmd_honey_multilang(args: argparse.Namespace) -> int:
    """Inject or scan multi-language Honey-Logic sentinels."""
    root = Path(args.root).resolve()
    if args.action == "inject":
        signature = args.signature or "local-dev-signature"
        project_id = args.project_id or root.name
        changed = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
                continue
            lang = honey_multilang_module.language_for_path(path)
            if not lang or (args.language and lang != args.language):
                continue
            try:
                result = honey_multilang_module.inject_honey_logic_file(path, project_id, signature, lang)
                changed.append(result)
            except Exception as exc:
                changed.append({"path": str(path), "changed": False, "error": str(exc)})
        print(json.dumps({"action": "inject", "results": changed}, indent=2, ensure_ascii=False))
        return 0
    if args.action == "scan":
        hits = honey_multilang_module.scan_multilang_honey(root)
        print(json.dumps({"action": "scan", "hits": hits}, indent=2, ensure_ascii=False))
        return 1 if hits else 0
    return 2


def cmd_osint_search(args: argparse.Namespace) -> int:
    """Search provider APIs for Honey-Logic terms and optionally enqueue hits."""
    terms = list(args.term or [])
    cfg = osint_module.OSINTConfig(
        provider=args.provider,
        token=args.token or "",
        base_url=args.base_url or "",
        per_page=args.per_page,
        sleep_seconds=args.sleep,
        enqueue=args.enqueue,
        database_url=args.database_url or "",
        workdir=args.workdir,
    )
    try:
        hits = osint_module.crawl_terms(terms, cfg)
    except Exception as exc:
        print(f"ERROR: OSINT search failed: {exc}", file=sys.stderr)
        return 2
    payload = {"hits": [h.to_dict() for h in hits]}
    if args.enqueue:
        payload["queue"] = osint_module.enqueue_hits(hits, cfg)
    out = json.dumps(payload, indent=2, ensure_ascii=False)
    print(out)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    return 0


def cmd_binary_provenance(args: argparse.Namespace) -> int:
    """Create or audit source-to-binary provenance metadata."""
    if args.binary_command == "create":
        prov = build_integration_module.create_binary_provenance(
            Path(args.root).resolve(),
            project_name=args.project_name or "",
            project_id=args.project_id or "",
        )
        if args.format == "json":
            output = json.dumps(prov.to_dict(), indent=2, ensure_ascii=False)
        elif args.format == "go-ldflags":
            output = build_integration_module.go_ldflags(prov, args.variable)
        elif args.format == "c-section":
            output = build_integration_module.c_section_source(prov, args.variable)
        else:
            output = prov.encode().decode("utf-8")
        print(output)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        return 0
    if args.binary_command == "append":
        prov = build_integration_module.create_binary_provenance(Path(args.root).resolve(), args.project_name or "", args.project_id or "")
        build_integration_module.append_provenance_blob(Path(args.binary), prov, Path(args.output) if args.output else None)
        print(json.dumps({"binary": args.binary, "output": args.output or args.binary, "provenance": prov.to_dict()}, indent=2))
        return 0
    if args.binary_command == "audit":
        print(json.dumps(build_integration_module.audit_binary(Path(args.binary)), indent=2, ensure_ascii=False))
        return 0
    return 2


def cmd_semantic_morph(args: argparse.Namespace) -> int:
    """Apply or verify semantic morph watermarking."""
    path = Path(args.path).resolve()
    cfg = semantic_morph_module.MorphConfig(
        backend=args.backend,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        lmstudio_url=args.lmstudio_url,
        lmstudio_model=args.lmstudio_model,
    )
    if args.morph_command == "embed":
        result = semantic_morph_module.morph_file(path, args.seed, cfg)
    else:
        result = semantic_morph_module.verify_morph_watermark(path.read_text(encoding="utf-8"), args.seed)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


# =========================================================================
# Enterprise IP Protection Suite v3 commands
# =========================================================================

def cmd_graph_compare(args: argparse.Namespace) -> int:
    original = Path(args.original).resolve()
    suspected = Path(args.suspected).resolve()
    report = graph_fingerprint_module.compare_graph_fingerprints(
        original,
        suspected,
        include_configs=args.include_configs,
        exclude_dirs=set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir or []),
    )
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report.get("graph_similarity", 0) < args.fail_threshold else 1


def cmd_bot(args: argparse.Namespace) -> int:
    result = bot_module.autofix_project(
        Path(args.root),
        license_id=args.license,
        owner=args.owner,
        project=args.project or "",
        include_configs=args.include_configs,
        update=args.update,
        dry_run=args.dry_run,
        create_pr=args.create_pr,
        branch=args.branch or "",
        base_branch=args.base or "",
        exclude_dirs=set(args.exclude_dir or []),
    )
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 1 if result.errors else 0


def cmd_intercept(args: argparse.Namespace) -> int:
    if args.intercept_command == "scan":
        text = Path(args.path).read_text(encoding="utf-8") if args.path != "-" else sys.stdin.read()
        res = llm_interceptor_module.scan_text(text)
        print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
        return 0 if res.allowed else 1

    target = args.target_url
    if args.target == "ollama" and not target:
        target = "http://localhost:11434"
    elif args.target == "lmstudio" and not target:
        target = "http://localhost:1234"
    elif args.target == "openai" and not target:
        target = "https://api.openai.com"
    policy = llm_interceptor_module.InterceptorPolicy(
        block_on_marker=not args.warn_only,
        block_on_honey_logic=not args.warn_only,
        warn_on_copyleft=True,
    )
    print(f"LicenseSeal interceptor listening on {args.host}:{args.port} -> {target}", file=sys.stderr)
    llm_interceptor_module.serve_proxy(args.host, args.port, target, policy)
    return 0


def cmd_sca(args: argparse.Namespace) -> int:
    report = sca_check_module.check_project(Path(args.root), args.license)
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    if args.fail_on_error and not report.ok:
        return 1
    return 0


def cmd_control_plane(args: argparse.Namespace) -> int:
    if args.control_command == "serve":
        try:
            import uvicorn
        except ImportError:
            print('ERROR: uvicorn is required for serving the control plane. Install "fastapi uvicorn".', file=sys.stderr)
            return 2
        from .control_plane.app import ControlPlaneConfig, create_app
        config = ControlPlaneConfig.from_env()
        app = create_app(config)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    if args.control_command == "event":
        from .control_plane.app import ControlPlaneConfig, emit_webhook, load_webhooks
        payload = {"type": args.event_type, "message": args.message}
        delivered = []
        config = ControlPlaneConfig.from_env()
        for hook in load_webhooks(config):
            if hook.get("event") in {args.event_type, "*"}:
                delivered.append({"id": hook.get("id"), "ok": emit_webhook(hook["url"], payload)})
        print(json.dumps({"event": payload, "delivered": delivered}, indent=2))
        return 0

    return 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="licenseseal",
        description="Inject, update, remove, audit and compare AI-readable license boundaries in source projects.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inject = sub.add_parser("inject", help="Inject or update license markers in project files")
    inject.add_argument("root", help="Project root directory")
    inject.add_argument("--license", required=True, help="SPDX license identifier, e.g. AGPL-3.0-or-later")
    inject.add_argument("--owner", required=True, help="Copyright owner")
    inject.add_argument("--project", help="Project name; defaults to directory name")
    inject.add_argument("--dry-run", action="store_true", help="Show what would change without writing files")
    inject.add_argument("--backup", action="store_true", help="Create .bak backup files before writing")
    inject.add_argument("--update", action="store_true", help="Replace existing LicenseSeal marker blocks with fresh metadata")
    inject.add_argument("--sign-key", help="Ed25519 private key PEM for AI_SIGNATURE")
    inject.add_argument("--write-policy", action="store_true", help="Write .ai-license-policy.json and AI_LICENSE_NOTICE.md")
    inject.add_argument("--include-configs", action="store_true", help="Also mark selected config files")
    inject.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    inject.add_argument("--include-git", action="store_true", help="Include Git commit info in signatures (Extension 4)")
    inject.set_defaults(func=cmd_inject)

    remove = sub.add_parser("remove", help="Remove LicenseSeal markers from project files")
    remove.add_argument("root", help="Project root directory")
    remove.add_argument("--dry-run", action="store_true", help="Show what would change without writing files")
    remove.add_argument("--backup", action="store_true", help="Create .bak backup files before writing")
    remove.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    remove.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    remove.set_defaults(func=cmd_remove)

    audit = sub.add_parser("audit", help="Check which files contain valid markers")
    audit.add_argument("root", help="Project root directory")
    audit.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    audit.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    audit.add_argument("--verify-key", help="Ed25519 public key PEM to verify AI_SIGNATURE entries")
    audit.add_argument("--format", choices=["text", "github"], default="text", help="Output format; github emits ::error annotations")
    audit.set_defaults(func=cmd_audit)

    compare = sub.add_parser("compare", help="Compare original and suspected project for structural similarity")
    compare.add_argument("original", help="Original project root")
    compare.add_argument("suspected", help="Suspected derived project root")
    compare.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    compare.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    compare.add_argument("--threshold", type=float, default=0.75, help="Suspicion threshold for CI exit-code; default 0.75")
    compare.add_argument("--output", help="Optional JSON report output path")
    compare.set_defaults(func=cmd_compare)

    keygen = sub.add_parser("keygen", help="Generate Ed25519 keypair for tamper-proof provenance")
    keygen.add_argument("--private-key", default=".licenseseal/private_key.pem", help="Private key output path")
    keygen.add_argument("--public-key", default=".licenseseal/public_key.pem", help="Public key output path")
    keygen.add_argument("--overwrite", action="store_true", help="Overwrite existing key files")
    keygen.set_defaults(func=cmd_keygen)

    web = sub.add_parser("web", help="Start local web interface")
    web.add_argument("--host", default="127.0.0.1", help="Bind host; default 127.0.0.1")
    web.add_argument("--port", type=int, default=8765, help="Port; default 8765")
    web.add_argument("--auto-port", action="store_true", help="Use next free port if selected port is busy")
    web.add_argument("--open-browser", action="store_true", help="Open browser automatically")
    web.set_defaults(func=cmd_web)

    # =========================================================================
    # Extension 1: Index Commands
    # =========================================================================
    index_parser = sub.add_parser("index", help="Index a project for fast similarity lookups")
    index_parser.add_argument("root", help="Project root directory")
    index_parser.add_argument("--db", help="SQLite database path; default: .licenseseal/signatures.db")
    index_parser.add_argument("--project", help="Project name; defaults to directory name")
    index_parser.add_argument("--include-configs", action="store_true", help="Also index selected config files")
    index_parser.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    index_parser.set_defaults(func=cmd_index)

    compare_db = sub.add_parser("compare-db", help="Compare suspected project against indexed originals")
    compare_db.add_argument("suspected", help="Suspected derived project root")
    compare_db.add_argument("--db", help="SQLite database path; default: .licenseseal/signatures.db")
    compare_db.add_argument("--project", required=True, help="Indexed project name to compare against")
    compare_db.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    compare_db.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    compare_db.add_argument("--threshold", type=float, default=0.75, help="Suspicion threshold; default 0.75")
    compare_db.add_argument("--output", help="Optional JSON report output path")
    compare_db.set_defaults(func=cmd_compare_db)

    index_list = sub.add_parser("index-list", help="List all indexed projects")
    index_list.add_argument("--db", help="SQLite database path; default: .licenseseal/signatures.db")
    index_list.set_defaults(func=cmd_index_list)

    index_remove = sub.add_parser("index-remove", help="Remove a project from the index")
    index_remove.add_argument("project", help="Project name to remove")
    index_remove.add_argument("--db", help="SQLite database path; default: .licenseseal/signatures.db")
    index_remove.set_defaults(func=cmd_index_remove)

    # =========================================================================
    # Extension 2: Semantic Search Commands
    # =========================================================================
    semantic = sub.add_parser("semantic", help="Compare projects using semantic embeddings")
    semantic.add_argument("original", help="Original project root")
    semantic.add_argument("suspected", help="Suspected derived project root")
    semantic.add_argument("--model", help="Sentence-transformers model name")
    semantic.add_argument("--device", default="auto", help="Device for embeddings (cpu/cuda)")
    semantic.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    semantic.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    semantic.add_argument("--threshold", type=float, default=0.85, help="Similarity threshold; default 0.85")
    semantic.add_argument("--output", help="Optional JSON report output path")
    semantic.set_defaults(func=cmd_semantic)

    # =========================================================================
    # Extension 3: Trust Infrastructure Commands
    # =========================================================================
    trust = sub.add_parser("trust", help="Decentralized trust infrastructure")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)

    trust_fetch = trust_sub.add_parser("fetch", help="Fetch public key from a domain")
    trust_fetch.add_argument("domain", help="Domain to fetch key from")
    trust_fetch.set_defaults(func=cmd_trust_fetch)

    trust_verify = trust_sub.add_parser("verify", help="Verify public key is associated with domain")
    trust_verify.add_argument("public_key", help="Public key PEM file")
    trust_verify.add_argument("domain", help="Domain to verify against")
    trust_verify.set_defaults(func=cmd_trust_verify)

    trust_init = trust_sub.add_parser("init", help="Initialize .well-known endpoint for domain")
    trust_init.add_argument("--output", required=True, help="Output path for .well-known file")
    trust_init.add_argument("--key-id", required=True, help="Key ID for the public key")
    trust_init.add_argument("--public-key", required=True, help="Public key PEM file")
    trust_init.add_argument("--owner", help="Owner name")
    trust_init.add_argument("--domain", action="append", help="Domain(s) to associate with key")
    trust_init.set_defaults(func=cmd_trust_init)

    # =========================================================================
    # Extension 4: Git History Commands
    # =========================================================================
    git = sub.add_parser("git", help="Git history integration")
    git_sub = git.add_subparsers(dest="git_command", required=True)

    git_info = git_sub.add_parser("info", help="Show Git commit information")
    git_info.add_argument("root", nargs="?", default=".", help="Project root directory")
    git_info.set_defaults(func=cmd_git_info)

    git_verify = git_sub.add_parser("verify", help="Verify commit hash exists")
    git_verify.add_argument("commit", help="Commit hash to verify")
    git_verify.add_argument("root", nargs="?", default=".", help="Project root directory")
    git_verify.set_defaults(func=cmd_git_verify)

    git_history = git_sub.add_parser("history", help="Show commit history")
    git_history.add_argument("root", nargs="?", default=".", help="Project root directory")
    git_history.add_argument("--max-count", type=int, default=20, help="Maximum number of commits")
    git_history.set_defaults(func=cmd_git_history)

    # =========================================================================
    # Extension 5: LSP Commands
    # =========================================================================
    lsp = sub.add_parser("lsp", help="Language Server Protocol for IDE integration")
    lsp.add_argument("--host", default="127.0.0.1", help="Bind host; default 127.0.0.1")
    lsp.add_argument("--port", type=int, default=8766, help="Port; default 8766")
    lsp.add_argument("--log", help="Log file path")
    lsp.add_argument("--strict", action="store_true", help="Enable strict validation mode")
    lsp.add_argument("--no-check-on-save", action="store_true", help="Disable check on file save")
    lsp.set_defaults(func=cmd_lsp)

    lsp_check = sub.add_parser("lsp-check", help="Check a file for license compliance")
    lsp_check.add_argument("file", help="File to check")
    lsp_check.set_defaults(func=cmd_lsp_check)

    lsp_validate = sub.add_parser("lsp-validate", help="Validate license compatibility")
    lsp_validate.add_argument("source_license", help="Source license (e.g., AGPL-3.0-or-later)")
    lsp_validate.add_argument("target_license", help="Target license (e.g., MIT)")
    lsp_validate.set_defaults(func=cmd_lsp_validate)

    # =========================================================================
    # Extension 1b: Watermark Commands
    # =========================================================================
    watermark = sub.add_parser("watermark", help="Invisible code watermarking")
    watermark_sub = watermark.add_subparsers(dest="watermark_command", required=True)

    watermark_embed = watermark_sub.add_parser("embed", help="Embed invisible watermark")
    watermark_embed.add_argument("root", help="Project root directory")
    watermark_embed.add_argument("--project-id", required=True, help="Project ID for watermark")
    watermark_embed.add_argument("--signature", help="Signature to embed")
    watermark_embed.add_argument("--strength", default="standard", choices=["minimal", "standard", "robust"], help="Watermark strength")
    watermark_embed.set_defaults(func=cmd_watermark_embed)

    watermark_extract = watermark_sub.add_parser("extract", help="Extract watermark from file")
    watermark_extract.add_argument("file", help="File to check")
    watermark_extract.set_defaults(func=cmd_watermark_extract)

    watermark_scan = watermark_sub.add_parser("scan", help="Scan project for watermarks")
    watermark_scan.add_argument("root", help="Project root directory")
    watermark_scan.set_defaults(func=cmd_watermark_scan)

    # =========================================================================
    # Extension 2b: Enterprise Registry Commands
    # =========================================================================
    registry = sub.add_parser("registry", help="Enterprise signature registry")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)

    registry_init = registry_sub.add_parser("init", help="Initialize enterprise registry")
    registry_init.add_argument("--database-url", default="postgresql://localhost:5432/licenseseal", help="PostgreSQL connection URL")
    registry_init.set_defaults(func=cmd_registry_init)

    registry_register = registry_sub.add_parser("register", help="Register project in enterprise registry")
    registry_register.add_argument("root", help="Project root directory")
    registry_register.add_argument("--database-url", help="PostgreSQL connection URL")
    registry_register.add_argument("--remote", help="Remote registry URL")
    registry_register.add_argument("--api-key", help="API key for remote registry")
    registry_register.add_argument("--owner", help="Project owner for registry metadata")
    registry_register.add_argument("--license-id", help="SPDX license identifier")
    registry_register.add_argument("--repository-url", help="Canonical repository URL")
    registry_register.add_argument("--project-id", help="Stable project ID used for honey-logic generation")
    registry_register.add_argument("--honey-density", type=int, default=1, help="Expected honey helpers per protected file")
    registry_register.add_argument("--no-honey", action="store_true", help="Do not register honey-logic fingerprints")
    registry_register.set_defaults(func=cmd_registry_register)

    registry_search = registry_sub.add_parser("search", help="Search registry for similar projects")
    registry_search.add_argument("--database-url", help="PostgreSQL connection URL")
    registry_search.add_argument("--remote", help="Remote registry URL")
    registry_search.add_argument("--api-key", help="API key for remote registry")
    registry_search.add_argument("--threshold", type=float, default=0.85, help="Similarity threshold")
    registry_search.set_defaults(func=cmd_registry_search)

    registry_list = registry_sub.add_parser("list", help="List projects in registry")
    registry_list.add_argument("--database-url", help="PostgreSQL connection URL")
    registry_list.set_defaults(func=cmd_registry_list)

    # =========================================================================
    # Extension 2c: Firehose Continuous Scanner
    # =========================================================================
    firehose = sub.add_parser("firehose", help="Continuous IP radar scanner")
    firehose_sub = firehose.add_subparsers(dest="firehose_command", required=True)

    firehose_scan = firehose_sub.add_parser("scan", help="Scan a local path or git URL and record evidence")
    firehose_scan.add_argument("candidate", help="Candidate local path or git clone URL")
    firehose_scan.add_argument("--database-url", help="PostgreSQL connection URL")
    firehose_scan.add_argument("--workdir", default=".licenseseal/firehose", help="Clone/cache work directory")
    firehose_scan.add_argument("--threshold", type=float, default=0.72, help="Alert threshold")
    firehose_scan.add_argument("--clone-depth", type=int, default=1, help="Git clone depth")
    firehose_scan.add_argument("--max-files", type=int, default=5000, help="Maximum files per candidate")
    firehose_scan.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    firehose_scan.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    firehose_scan.add_argument("--no-record", action="store_true", help="Do not persist scan/evidence rows")
    firehose_scan.add_argument("--output", help="Optional JSON report output path")
    firehose_scan.set_defaults(func=cmd_firehose_scan)
    firehose_enqueue = firehose_sub.add_parser("enqueue", help="Enqueue a candidate scan for Celery/Redis workers")
    firehose_enqueue.add_argument("candidate", help="Candidate local path or git clone URL")
    firehose_enqueue.add_argument("--database-url", help="PostgreSQL connection URL")
    firehose_enqueue.add_argument("--workdir", default=".licenseseal/firehose-workers", help="Worker clone/cache directory")
    firehose_enqueue.add_argument("--threshold", type=float, default=0.72, help="Alert threshold")
    firehose_enqueue.add_argument("--clone-depth", type=int, default=1, help="Git clone depth")
    firehose_enqueue.add_argument("--max-files", type=int, default=5000, help="Maximum files per candidate")
    firehose_enqueue.add_argument("--include-configs", action="store_true", help="Also scan selected config files")
    firehose_enqueue.add_argument("--no-record", action="store_true", help="Do not persist scan/evidence rows")
    firehose_enqueue.set_defaults(func=cmd_firehose_enqueue)

    firehose_worker = firehose_sub.add_parser("worker", help="Show distributed worker startup command")
    firehose_worker.set_defaults(func=cmd_firehose_worker)


    # =========================================================================
    # Extension 2d: Red-Team Watermark Stress Testing
    # =========================================================================
    stress = sub.add_parser("stress-test", help="Defensively test watermark survival under rewrites")
    stress.add_argument("root", help="Project root directory")
    stress.add_argument("--sample-size", type=int, default=5, help="Number of Python files to sample")
    stress.add_argument("--mode", choices=["local", "ollama", "lmstudio"], default="local", help="Rewrite backend")
    stress.add_argument("--seed", type=int, default=1337, help="Deterministic sampling seed")
    stress.add_argument("--threshold", type=float, default=0.8, help="Minimum acceptable survival rate")
    stress.add_argument("--output-dir", help="Directory for rewritten samples")
    stress.add_argument("--output", help="Optional JSON report output path")
    stress.add_argument("--ollama-url", default="http://localhost:11434/api/generate", help="Ollama generate endpoint")
    stress.add_argument("--ollama-model", default="codellama", help="Ollama model name")
    stress.add_argument("--lmstudio-url", default="http://localhost:1234/v1/chat/completions", help="LM Studio OpenAI-compatible chat endpoint")
    stress.add_argument("--lmstudio-model", default="local-model", help="LM Studio model name")
    stress.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude")
    stress.set_defaults(func=cmd_stress_test)

    # =========================================================================
    # Enterprise IP Protection Suite: Polyglot Honey-Logic
    # =========================================================================
    honey_ml = sub.add_parser("honey-multilang", help="Inject or scan Honey-Logic in Python/JS/TS/Go/Rust/Java")
    honey_ml.add_argument("action", choices=["inject", "scan"], help="Action to perform")
    honey_ml.add_argument("root", help="Project root directory")
    honey_ml.add_argument("--project-id", help="Project identifier for deterministic sentinels")
    honey_ml.add_argument("--signature", help="Project signature/secret seed for deterministic sentinels")
    honey_ml.add_argument("--language", choices=list(honey_multilang_module.SUPPORTED_LANGUAGES), help="Restrict to one language")
    honey_ml.set_defaults(func=cmd_honey_multilang)

    # =========================================================================
    # Enterprise IP Protection Suite: OSINT Firehose Discovery
    # =========================================================================
    osint = sub.add_parser("osint", help="Search GitHub/GitLab for Honey-Logic and enqueue Firehose scans")
    osint.add_argument("--provider", choices=["github", "gitlab"], default="github", help="Search provider")
    osint.add_argument("--term", action="append", required=True, help="Search term, e.g. _ls_fold_ab12cd")
    osint.add_argument("--token", help="API token; defaults to provider env var")
    osint.add_argument("--base-url", help="Custom API base URL for enterprise Git hosts")
    osint.add_argument("--per-page", type=int, default=20, help="Provider result page size")
    osint.add_argument("--sleep", type=float, default=0.0, help="Delay between term searches")
    osint.add_argument("--enqueue", action="store_true", help="Enqueue discovered repositories into Firehose queue")
    osint.add_argument("--database-url", help="Registry database URL for queued workers")
    osint.add_argument("--workdir", default=".licenseseal/firehose-osint", help="Worker clone/cache directory")
    osint.add_argument("--output", help="Optional JSON output path")
    osint.set_defaults(func=cmd_osint_search)

    # =========================================================================
    # Enterprise IP Protection Suite: Binary Provenance
    # =========================================================================
    binary = sub.add_parser("binary", help="Create and audit source-to-binary provenance")
    binary_sub = binary.add_subparsers(dest="binary_command", required=True)

    binary_create = binary_sub.add_parser("create", help="Create build metadata for a project")
    binary_create.add_argument("root", help="Project root")
    binary_create.add_argument("--project-name", help="Project display name")
    binary_create.add_argument("--project-id", help="Stable project identifier")
    binary_create.add_argument("--format", choices=["json", "go-ldflags", "c-section", "blob"], default="json")
    binary_create.add_argument("--variable", default="main.LicenseSealProvenance", help="Go variable or C symbol name")
    binary_create.add_argument("--output", help="Optional output file")
    binary_create.set_defaults(func=cmd_binary_provenance)

    binary_append = binary_sub.add_parser("append", help="Append a provenance blob to a binary artifact")
    binary_append.add_argument("root", help="Project root")
    binary_append.add_argument("binary", help="Binary artifact path")
    binary_append.add_argument("--project-name", help="Project display name")
    binary_append.add_argument("--project-id", help="Stable project identifier")
    binary_append.add_argument("--output", help="Output artifact path; defaults to in-place")
    binary_append.set_defaults(func=cmd_binary_provenance)

    binary_audit = binary_sub.add_parser("audit", help="Audit a binary artifact for LicenseSeal provenance")
    binary_audit.add_argument("binary", help="Binary, JAR, ELF or PE path")
    binary_audit.set_defaults(func=cmd_binary_provenance)

    # =========================================================================
    # Enterprise IP Protection Suite: Semantic Morph Watermarking
    # =========================================================================
    morph = sub.add_parser("semantic-morph", help="Embed/verify morphing semantic watermarks via local/Ollama/LM Studio")
    morph_sub = morph.add_subparsers(dest="morph_command", required=True)

    morph_embed = morph_sub.add_parser("embed", help="Embed a morphing semantic watermark into a Python file")
    morph_embed.add_argument("path", help="Python file")
    morph_embed.add_argument("--seed", required=True, help="Secret watermark seed")
    morph_embed.add_argument("--backend", choices=["local", "ollama", "lmstudio"], default="local")
    morph_embed.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    morph_embed.add_argument("--ollama-model", default="codellama")
    morph_embed.add_argument("--lmstudio-url", default="http://localhost:1234/v1/chat/completions")
    morph_embed.add_argument("--lmstudio-model", default="local-model")
    morph_embed.set_defaults(func=cmd_semantic_morph)

    morph_verify = morph_sub.add_parser("verify", help="Verify a morphing semantic watermark invariant")
    morph_verify.add_argument("path", help="Python file")
    morph_verify.add_argument("--seed", required=True, help="Secret watermark seed")
    morph_verify.add_argument("--backend", default="local")
    morph_verify.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    morph_verify.add_argument("--ollama-model", default="codellama")
    morph_verify.add_argument("--lmstudio-url", default="http://localhost:1234/v1/chat/completions")
    morph_verify.add_argument("--lmstudio-model", default="local-model")
    morph_verify.set_defaults(func=cmd_semantic_morph)

    # =========================================================================
    # Extension 3b: Cross-Lingual Commands
    # =========================================================================
    cross_lingual = sub.add_parser("cross-lingual", help="Cross-lingual code detection")
    cross_lingual.add_argument("original", help="Original project root")
    cross_lingual.add_argument("suspected", help="Suspected derived project root")
    cross_lingual.add_argument("--model", default="jina-code", choices=["jina-code", "codebert", "starCoder", "minilm"], help="Embedding model")
    cross_lingual.add_argument("--device", default="auto", help="Device (cpu/cuda)")
    cross_lingual.add_argument("--threshold", type=float, default=0.80, help="Similarity threshold")
    cross_lingual.add_argument("--output", help="Output JSON path")
    cross_lingual.set_defaults(func=cmd_cross_lingual)

    # =========================================================================
    # Extension 4b: SBOM Commands
    # =========================================================================
    sbom = sub.add_parser("sbom", help="SBOM generation (SPDX, CycloneDX)")
    sbom_sub = sbom.add_subparsers(dest="sbom_command", required=True)

    sbom_export = sbom_sub.add_parser("export", help="Export project as SBOM")
    sbom_export.add_argument("root", help="Project root directory")
    sbom_export.add_argument("--format", default="cyclonedx", choices=["spdx", "cyclonedx"], help="SBOM format")
    sbom_export.add_argument("--output", help="Output SBOM file path")
    sbom_export.set_defaults(func=cmd_sbom_export)

    sbom_validate = sbom_sub.add_parser("validate", help="Validate a SBOM file")
    sbom_validate.add_argument("file", help="SBOM file to validate")
    sbom_validate.set_defaults(func=cmd_sbom_validate)

    # =========================================================================
    # Extension 5b: Legal Report Commands
    # =========================================================================
    report = sub.add_parser("report", help="Generate legal evidence reports")
    report.add_argument("original", help="Original project root")
    report.add_argument("suspected", help="Suspected derived project root")
    report.add_argument("--format", default="pdf", choices=["pdf", "html", "markdown"], help="Report format")
    report.add_argument("--output", required=True, help="Output report path")
    report.add_argument("--no-diff", action="store_true", help="Exclude code diff")
    report.add_argument("--no-git", action="store_true", help="Exclude Git history")
    report.set_defaults(func=cmd_report)

    dmca = sub.add_parser("dmca", help="Generate DMCA takedown notice")
    dmca.add_argument("original", help="Original project root")
    dmca.add_argument("suspected", help="Suspected repository URL or path")
    dmca.add_argument("--output", required=True, help="Output notice path")
    dmca.set_defaults(func=cmd_dmca)

    certificate = sub.add_parser("certificate", help="Generate compliance certificate")
    certificate.add_argument("root", help="Project root directory")
    certificate.add_argument("--output", required=True, help="Output certificate path")
    certificate.set_defaults(func=cmd_certificate)


    # =========================================================================
    # Enterprise IP Protection Suite v3: CFG/DFG graph fingerprinting
    # =========================================================================
    graph = sub.add_parser("graph", help="CFG/DFG graph fingerprint comparison")
    graph_sub = graph.add_subparsers(dest="graph_command", required=True)
    graph_compare = graph_sub.add_parser("compare", help="Compare projects using CFG/DFG fingerprints")
    graph_compare.add_argument("original", help="Original project root")
    graph_compare.add_argument("suspected", help="Suspected project root")
    graph_compare.add_argument("--include-configs", action="store_true")
    graph_compare.add_argument("--exclude-dir", action="append", default=[])
    graph_compare.add_argument("--fail-threshold", type=float, default=1.1, help="Return non-zero if similarity is >= threshold")
    graph_compare.add_argument("--output", help="Output JSON file")
    graph_compare.set_defaults(func=cmd_graph_compare)

    # =========================================================================
    # Enterprise IP Protection Suite v3: Auto-remediation bot
    # =========================================================================
    bot = sub.add_parser("bot", help="Auto-remediation bot for CI/CD")
    bot_sub = bot.add_subparsers(dest="bot_command", required=True)
    bot_fix = bot_sub.add_parser("autofix", help="Inject/update markers and optionally create a PR")
    bot_fix.add_argument("root", help="Project root")
    bot_fix.add_argument("--license", required=True, help="Target SPDX license")
    bot_fix.add_argument("--owner", required=True, help="Copyright owner")
    bot_fix.add_argument("--project", help="Project name")
    bot_fix.add_argument("--include-configs", action="store_true")
    bot_fix.add_argument("--update", action="store_true", default=True)
    bot_fix.add_argument("--dry-run", action="store_true")
    bot_fix.add_argument("--create-pr", action="store_true")
    bot_fix.add_argument("--branch", help="Autofix branch name")
    bot_fix.add_argument("--base", help="PR base branch")
    bot_fix.add_argument("--exclude-dir", action="append", default=[])
    bot_fix.set_defaults(func=cmd_bot)

    # =========================================================================
    # Enterprise IP Protection Suite v3: LLM interceptor
    # =========================================================================
    intercept = sub.add_parser("intercept", help="LLM prompt/response interceptor")
    intercept_sub = intercept.add_subparsers(dest="intercept_command", required=True)
    intercept_scan = intercept_sub.add_parser("scan", help="Scan a file or stdin for protected code indicators")
    intercept_scan.add_argument("path", help="File path or '-' for stdin")
    intercept_scan.set_defaults(func=cmd_intercept)
    intercept_serve = intercept_sub.add_parser("serve", help="Serve a local Ollama/LM Studio/OpenAI-compatible proxy")
    intercept_serve.add_argument("--host", default="127.0.0.1")
    intercept_serve.add_argument("--port", type=int, default=11435)
    intercept_serve.add_argument("--target", choices=["ollama", "lmstudio", "openai"], default="ollama")
    intercept_serve.add_argument("--target-url", default="", help="Override target base URL")
    intercept_serve.add_argument("--warn-only", action="store_true", help="Warn but do not block marker/honey-logic findings")
    intercept_serve.set_defaults(func=cmd_intercept)

    # =========================================================================
    # Enterprise IP Protection Suite v3: SCA/license conflict checking
    # =========================================================================
    sca = sub.add_parser("sca", help="Software composition/license conflict checks")
    sca_sub = sca.add_subparsers(dest="sca_command", required=True)
    sca_check = sca_sub.add_parser("check", help="Check project manifests against a target license")
    sca_check.add_argument("root", help="Project root")
    sca_check.add_argument("--license", required=True, help="Target SPDX license to inject/use")
    sca_check.add_argument("--fail-on-error", action="store_true")
    sca_check.set_defaults(func=cmd_sca)

    # =========================================================================
    # Enterprise IP Protection Suite v3: Enterprise Control Plane
    # =========================================================================
    control = sub.add_parser("control-plane", help="Enterprise Control Plane API")
    control_sub = control.add_subparsers(dest="control_command", required=True)
    control_serve = control_sub.add_parser("serve", help="Serve the FastAPI control plane")
    control_serve.add_argument("--host", default="127.0.0.1")
    control_serve.add_argument("--port", type=int, default=8787)
    control_serve.set_defaults(func=cmd_control_plane)
    control_event = control_sub.add_parser("event", help="Emit a local webhook event")
    control_event.add_argument("event_type")
    control_event.add_argument("--message", default="")
    control_event.set_defaults(func=cmd_control_plane)


    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
