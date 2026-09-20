"""Mark existing duplicate findings in the DB as is_duplicate=True.

This is a one-time cleanup script to run AFTER the worker.py dedup fix
has been deployed. It scans all findings, groups by (scan_id, title,
normalized_url), and marks all but the first in each group as duplicates.

Usage:
    cd /home/z/my-project/pentest_platform_modified
    python /home/z/my-project/scripts/dedup_existing_findings.py
"""
import os
import sys

# Make sure the project root is on sys.path so 'app' is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Try a few candidate locations
for candidate in [
    '/home/z/my-project/pentest_platform_modified',
    PROJECT_ROOT,
]:
    if os.path.isdir(os.path.join(candidate, 'app')):
        sys.path.insert(0, candidate)
        os.chdir(candidate)
        break

from app import create_app
from app.extensions import db
from app.models.finding import Finding


def norm_url(u):
    if not u:
        return ''
    u = str(u).strip()
    if '://' not in u:
        return u  # not a URL, return as-is
    scheme, rest = u.split('://', 1)
    scheme = scheme.lower()
    if '/' in rest:
        host_part, path_part = rest.split('/', 1)
    else:
        host_part = rest
        path_part = ''
    if host_part.endswith(':80'):
        host_part = host_part[:-3]
    elif host_part.endswith(':443'):
        host_part = host_part[:-4]
    host_part = host_part.lower()
    path_part = path_part.rstrip('/')
    if path_part:
        return f'{scheme}://{host_part}/{path_part}'
    return f'{scheme}://{host_part}'


def main():
    app = create_app()
    with app.app_context():
        all_findings = Finding.query.order_by(Finding.id).all()
        print(f"Total findings in DB: {len(all_findings)}")

        # Group by (scan_id, title, normalized_url)
        groups = {}
        for f in all_findings:
            key = (f.scan_id, f.title or '', norm_url(f.url))
            groups.setdefault(key, []).append(f)

        # For each group with >1 finding, mark all but the lowest-id one
        # as is_duplicate=True and point duplicate_of_id to the keeper.
        total_marked = 0
        for key, findings in groups.items():
            if len(findings) <= 1:
                continue
            # Sort by id ascending; the first is the "keeper"
            findings.sort(key=lambda x: x.id)
            keeper = findings[0]
            for dup in findings[1:]:
                if not dup.is_duplicate:  # don't re-mark
                    dup.is_duplicate = True
                    dup.duplicate_of_id = keeper.id
                    total_marked += 1

        print(f"Marking {total_marked} duplicate finding(s) as is_duplicate=True...")
        db.session.commit()
        print("Done.")

        # Print a summary per scan
        from app.models.scan import Scan
        scans = Scan.query.all()
        print("\nPer-scan summary:")
        for s in scans:
            total = Finding.query.filter_by(scan_id=s.id).count()
            dups = Finding.query.filter_by(scan_id=s.id, is_duplicate=True).count()
            visible = total - dups
            print(f"  Scan #{s.id} ({s.name}): {total} total, {dups} duplicates marked, {visible} visible")


if __name__ == '__main__':
    main()
