"""Build nbdev notebooks from plain-Python sources in `nbsrc/`.

Notebooks are nbdev's source of truth, but hand-editing .ipynb JSON is painful.
Each `nbsrc/<name>.py` uses `# %%` cell markers and is compiled to `nbs/<name>.ipynb`:

    # %% md          -> markdown cell
    # %% export      -> code cell prefixed with `#| export`
    # %% hide        -> code cell prefixed with `#| hide`
    # %% code        -> plain code cell (tests etc.)
    # %% noeval      -> code cell prefixed with `#| eval: False`

Cell ids are content-hashed so rebuilding an unchanged cell keeps its id, which
keeps `_modidx.py` and the generated `# %% ../nbs/...` comments stable.

Usage: python tools/nbbuild.py [name ...]
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC, NBS = ROOT / 'nbsrc', ROOT / 'nbs'

DIRECTIVES = {'export': '#| export', 'hide': '#| hide', 'noeval': '#| eval: False', 'code': None}


def _cells(text):
    "Split a marker-annotated source file into (kind, body) pairs."
    kind, buf = None, []
    for line in text.splitlines():
        if line.startswith('# %%'):
            if kind is not None:
                yield kind, '\n'.join(buf)
            kind, buf = line[4:].strip() or 'code', []
        else:
            buf.append(line)
    if kind is not None:
        yield kind, '\n'.join(buf)


def _src_lines(body):
    "JSON `source` is a list of lines, each keeping its trailing newline except the last."
    lines = body.split('\n')
    return [l + '\n' for l in lines[:-1]] + lines[-1:]


def _cell(kind, body):
    body = body.strip('\n')
    if not body:
        return None
    if kind == 'md':
        # markdown cells are written as `# `-prefixed comments in the .py source
        body = '\n'.join(l[2:] if l.startswith('# ') else l.lstrip('#') for l in body.split('\n'))
        cell = dict(cell_type='markdown', metadata={}, source=_src_lines(body.strip('\n')))
    else:
        if kind not in DIRECTIVES:
            raise ValueError(f'unknown cell marker: {kind!r}')
        directive = DIRECTIVES[kind]
        if directive:
            body = f'{directive}\n{body}'
        cell = dict(cell_type='code', execution_count=None, metadata={}, outputs=[], source=_src_lines(body))
    cell['id'] = hashlib.sha1(''.join(cell['source']).encode()).hexdigest()[:8]
    return cell


def build(path):
    cells = [c for c in (_cell(k, b) for k, b in _cells(path.read_text())) if c]
    nb = dict(cells=cells,
              metadata=dict(kernelspec=dict(display_name='python3', language='python', name='python3')),
              nbformat=4, nbformat_minor=5)
    out = NBS / f'{path.stem}.ipynb'
    out.write_text(json.dumps(nb, indent=1) + '\n')
    return out, len(cells)


if __name__ == '__main__':
    names = sys.argv[1:]
    srcs = [SRC / f'{n}.py' for n in names] if names else sorted(SRC.glob('*.py'))
    for s in srcs:
        out, n = build(s)
        print(f'{s.name} -> {out.relative_to(ROOT)} ({n} cells)')
