"""Export learned patterns (source='learned') as .md technique files.

Learned patterns are host-specific and stored only in DB. This command
converts them to Markdown technique files in the techniques/ directory,
making them permanent and collaborative (each pattern = separate file,
no merge conflicts).

Usage:
  # Preview what would be exported (stdout)
  docker compose exec backend python manage.py export_learned

  # Write .md files to techniques/<vuln_type>/
  docker compose exec backend python manage.py export_learned --write

  # Promote in DB + write files
  docker compose exec backend python manage.py export_learned --write --promote

  # Only export patterns that succeeded at least 2 times
  docker compose exec backend python manage.py export_learned --min-succeeded 2 --write
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import yaml
from django.core.management.base import BaseCommand
from django.db import transaction

from api.models import PayloadPattern, VulnerabilityEntry

TECHNIQUES_DIR = Path(__file__).resolve().parent / "techniques"


def _strip_host_prefix(name: str) -> str:
    """Remove [novel@host] prefix from learned pattern names."""
    return re.sub(r"^\[novel@[^\]]+\]\s*", "", name)


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _clean_name(name: str, vuln_type: str, pattern_id: str) -> str:
    clean = _strip_host_prefix(name).strip()
    if not clean or clean == vuln_type:
        clean = f"learned_{vuln_type}_{str(pattern_id)[:8]}"
    return _slugify(clean)[:200]


def _clean_tags(tags: list | None, host: str | None) -> list[str]:
    if not tags:
        return []
    skip = {"learned", "novel"}
    if host:
        skip.add(host)
    return [t for t in tags if t not in skip]


def pattern_to_md(p: PayloadPattern) -> tuple[str, str, str]:
    """Convert a learned PayloadPattern to (filename, vuln_type, markdown_content)."""
    meta = p.attack_metadata or {}
    name = _clean_name(p.name, p.vuln_type, str(p.pattern_id))
    tags = _clean_tags(p.tags, p.target_host)
    if p.vuln_type and p.vuln_type not in tags:
        tags.insert(0, p.vuln_type)

    novelty = meta.get("novelty_reason", "")
    notes = meta.get("notes", "")
    endpoint = meta.get("endpoint", "")

    applies_when = novelty or notes or f"Learned from confirmed {p.vuln_type} finding"

    title = _strip_host_prefix(p.name).strip() or name
    title = title.replace("_", " ").title()

    # Build frontmatter
    front = {
        "name": name,
        "vuln_type": p.vuln_type,
    }
    if p.sub_technique:
        front["sub_technique"] = p.sub_technique
    front["category"] = "exploitation"
    front["safety_level"] = p.safety_level or "safe"
    if tags:
        front["tags"] = tags

    # Build markdown body
    lines = []
    lines.append("---")
    lines.append(yaml.dump(front, allow_unicode=True, default_flow_style=False, sort_keys=False).strip())
    lines.append("---")
    lines.append("")
    lines.append(f"# {title}")
    lines.append("")

    lines.append("## When to Apply")
    lines.append("")
    lines.append(applies_when)
    lines.append("")

    prereqs = [f"Target vulnerable to {p.vuln_type}"]
    lines.append("## Prerequisites")
    lines.append("")
    for pr in prereqs:
        lines.append(f"- {pr}")
    lines.append("")

    if p.request_template:
        lines.append("## Steps")
        lines.append("")
        lines.append(f"1. Send the following payload:")
        lines.append("")
        lines.append("```")
        lines.append(p.request_template[:500])
        lines.append("```")
        lines.append("")
        lines.append("2. Verify with oracle or response analysis.")
        lines.append("")
    elif novelty:
        lines.append("## Steps")
        lines.append("")
        lines.append(f"1. {novelty}")
        lines.append("")

    if p.request_template:
        lines.append("## Code Template")
        lines.append("")
        lines.append("```")
        lines.append(p.request_template)
        lines.append("```")
        lines.append("")

    if endpoint or p.times_succeeded:
        lines.append("## Examples")
        lines.append("")
        lines.append("### Example 1")
        lines.append("")
        if endpoint:
            lines.append(f"- **original_endpoint**: {endpoint}")
        if meta.get("oracle_signatures"):
            lines.append(f"- **oracle_signatures**: `{json.dumps(meta['oracle_signatures'], ensure_ascii=False)}`")
        if p.times_succeeded:
            lines.append("")
            lines.append(f"Succeeded {p.times_succeeded}/{p.times_used} times.")
        lines.append("")

    md_content = "\n".join(lines)
    filename = f"{_slugify(name)}.md"

    return filename, p.vuln_type, md_content


class Command(BaseCommand):
    help = "Export learned patterns as .md technique files"

    def add_arguments(self, parser):
        parser.add_argument(
            "--min-succeeded", type=int, default=1,
            help="Only export patterns with times_succeeded >= N (default: 1)",
        )
        parser.add_argument(
            "--write", action="store_true",
            help="Write .md files to techniques/ directory (default: preview only)",
        )
        parser.add_argument(
            "--promote", action="store_true",
            help="Also promote patterns in DB: source='learned' → 'technique'",
        )
        parser.add_argument(
            "--target-dir", type=str, default=None,
            help="Override output directory (default: techniques/<vuln_type>/)",
        )

    def handle(self, *args, **opts):
        min_succ = opts["min_succeeded"]

        qs = PayloadPattern.objects.filter(
            source="learned", is_active=True,
            times_succeeded__gte=min_succ,
        ).order_by("-times_succeeded", "-times_used")

        already_exported = {
            p.pattern_id for p in qs
            if (p.attack_metadata or {}).get("exported_to_md")
        }

        patterns = [p for p in qs if p.pattern_id not in already_exported]

        if not patterns:
            self.stdout.write(self.style.WARNING(
                f"No learned patterns to export "
                f"(min_succeeded={min_succ}, {len(already_exported)} already exported)"
            ))
            return

        self.stdout.write(f"Found {len(patterns)} learned patterns to export\n")

        existing_names = set(
            PayloadPattern.objects.filter(source="technique")
            .values_list("name", flat=True)
        )

        out_dir = Path(opts["target_dir"]) if opts.get("target_dir") else TECHNIQUES_DIR
        exported = []

        for p in patterns:
            filename, vuln_type, md_content = pattern_to_md(p)
            clean_name = _clean_name(p.name, p.vuln_type, str(p.pattern_id))

            if clean_name in existing_names:
                self.stdout.write(self.style.WARNING(
                    f"  SKIP (duplicate): {clean_name} ({vuln_type})"
                ))
                continue

            if opts.get("write"):
                target_dir = out_dir / vuln_type
                target_dir.mkdir(parents=True, exist_ok=True)
                filepath = target_dir / filename
                filepath.write_text(md_content, encoding="utf-8")
                self.stdout.write(f"  WROTE: {filepath.relative_to(out_dir)}")

                meta = p.attack_metadata or {}
                meta["exported_to_md"] = True
                meta["exported_date"] = str(date.today())
                p.attack_metadata = meta
                p.save(update_fields=["attack_metadata"])
            else:
                self.stdout.write(f"\n{'='*60}")
                self.stdout.write(f"  File: {vuln_type}/{filename}")
                self.stdout.write(f"{'='*60}")
                self.stdout.write(md_content)

            exported.append({"name": clean_name, "vuln_type": vuln_type, "file": filename})
            existing_names.add(clean_name)

        if opts.get("promote") and opts.get("write"):
            self._promote(patterns, exported)

        self.stdout.write(self.style.SUCCESS(
            f"\nExported {len(exported)} learned patterns"
            + (" (files written)" if opts.get("write") else " (preview only, use --write to save)")
        ))

    @transaction.atomic
    def _promote(self, patterns: list, exported: list):
        """Promote exported patterns in DB from learned → technique."""
        vuln_by_type = {v.vuln_type: v for v in VulnerabilityEntry.objects.all()}
        exported_names = {e["name"] for e in exported}

        for p in patterns:
            clean_name = _clean_name(p.name, p.vuln_type, str(p.pattern_id))
            if clean_name not in exported_names:
                continue
            vuln = vuln_by_type.get(p.vuln_type)
            p.source = "technique"
            p.name = clean_name
            p.target_host = None
            p.category = "exploitation"
            p.vulnerability = vuln
            p.mutation_type = "original"
            p.save()
            self.stdout.write(f"  PROMOTED: {clean_name} ({p.vuln_type})")

        from api.embedding_service import (
            EMBEDDING_MODEL,
            embed_documents,
            is_available as embeddings_available,
        )
        if embeddings_available():
            promoted = [p for p in patterns
                        if _clean_name(p.name, p.vuln_type, str(p.pattern_id)) in exported_names]
            if not promoted:
                return
            texts = []
            for p in promoted:
                meta = p.attack_metadata or {}
                parts = [
                    f"name: {meta.get('name', p.name)}",
                    f"vuln_type: {p.vuln_type}",
                    f"applies_when: {meta.get('applies_when', '')}",
                    f"prerequisites: {' / '.join(meta.get('prerequisites') or [])}",
                    f"steps: {meta.get('technique_steps_md', '')[:500]}",
                    f"tags: {', '.join(meta.get('tags') or p.tags or [])}",
                ]
                texts.append("\n".join(parts))
            vectors = embed_documents(texts)
            if vectors:
                for p, vec in zip(promoted, vectors):
                    p.embedding = vec
                    p.embedding_model = EMBEDDING_MODEL
                    p.save(update_fields=["embedding", "embedding_model"])
                self.stdout.write(self.style.SUCCESS(
                    f"  Embeddings saved for {len(vectors)} promoted patterns"
                ))
