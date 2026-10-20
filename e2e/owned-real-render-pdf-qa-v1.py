#!/usr/bin/env python3
"""Offline, synthetic owned-fixture PDF QA; invokes only root-provisioned Poppler.
No network, service credentials, source mutation or PDF rewrite. Root must run
inside its bounded QA environment and inspect the emitted PNGs before acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import selectors
import signal
import time
import unicodedata
from html.parser import HTMLParser

MAX_PDF = 128 << 20  # existing intake maximum; not a product limit increase
MAX_TEXT = 4 << 20

def refuse(message):
    raise RuntimeError(message)

def sha_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()

def compact(text):
    return ''.join(unicodedata.normalize('NFC', text).split())

class VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.nodes = []
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden:
            self.hidden -= 1
    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.nodes.append(data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--pdfinfo', required=True)
    parser.add_argument('--pdffonts', required=True)
    parser.add_argument('--pdftotext', required=True)
    parser.add_argument('--pdftoppm', required=True)
    args = parser.parse_args()
    root = Path(args.artifacts)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        refuse('absolute owned artifact directory required')
    tools = {}
    for name in ('pdfinfo', 'pdffonts', 'pdftotext', 'pdftoppm'):
        tool = Path(getattr(args, name))
        if not tool.is_absolute() or not tool.is_file() or not os.access(tool, os.X_OK):
            refuse('explicit provisioned Poppler executable required')
        tools[name] = str(tool)
    receipt_path = root / 'backend-receipt.json'
    if receipt_path.is_symlink() or receipt_path.stat().st_size > 1 << 20:
        refuse('bounded regular backend receipt required')
    receipt = json.loads(receipt_path.read_text())
    if receipt.get('result') != 'pass' or receipt.get('four_terminal_artifacts_per_document') is not True:
        refuse('successful exact backend four-artifact receipt required')
    browser_path = root / 'browser-receipt.json'
    if browser_path.is_symlink() or not browser_path.is_file() or browser_path.stat().st_size > 1 << 20:
        refuse('bounded regular browser receipt required')
    browser = json.loads(browser_path.read_text())
    if browser.get('result') != 'pass' or browser.get('browser_close_returned') is not True or browser.get('foreign_request_attempts') != 0 or browser.get('browser_error_count') != 0:
        refuse('actual browser security/completion receipt required')
    if browser.get('renderer_version') != receipt.get('renderer_version') or browser.get('renderer_image_id_supplied_by_root') != receipt.get('renderer_image_id_supplied_by_root'):
        refuse('browser/backend renderer fixture identities differ')
    observations_by_label = {entry.get('label'): entry for entry in browser.get('observations', [])}
    if set(observations_by_label) != {'manual-autosave', 'party-1', 'party-2'} or len(browser.get('observations', [])) != 3:
        refuse('exact actual three-party browser observations required')
    expected = receipt.get('artifact_sha256', {})
    for label, document, final_name in [('manual-autosave', receipt.get('manual_document_id'), 'autosave-final.pdf'), ('party-2', receipt.get('document_id'), 'profile-final.pdf')]:
        observed = observations_by_label[label]
        if observed.get('document_id') != document or observed.get('completed') is not True or observed.get('final_pdf_sha256') != expected.get(final_name):
            refuse('actual browser final download differs from exact stored artifact')
    if observations_by_label['party-1'].get('completed') is not False or observations_by_label['party-1'].get('final_pdf_sha256') is not None:
        refuse('first-party browser ordering differs')
    required = {label + suffix for label in ('profile', 'autosave') for suffix in
                ('-source.pdf', '-final.pdf', '-certificate.pdf', '-certificate-payload.html', '-certificate-signature.txt')}
    if set(expected) != required:
        refuse('exact ten-file source plus four-terminal-artifact inventory required')
    for name in required:
        file = root / name
        if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_PDF or not re.fullmatch('[0-9a-f]{64}', expected[name]) or sha_file(file) != expected[name]:
            refuse('artifact file or committed digest differs')
    qa = root / 'pdf-qa'
    qa.mkdir(mode=0o700)  # fresh only; never reinterpret an old receipt as this run
    os.chmod(qa, 0o700)
    observations = {}
    tool_versions = {}
    environment = {'PATH': os.pathsep.join(sorted({str(Path(t).parent) for t in tools.values()})),
                   'HOME': '/nonexistent', 'TMPDIR': str(qa), 'LC_ALL': 'C', 'LANG': 'C'}
    def execute(command, seconds, cap):
        # Drain both actual pipes concurrently, rejecting before retaining more
        # than cap bytes per channel. No shell or unbounded communicate buffer.
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=environment, start_new_session=True)
        stdout, stderr = bytearray(), bytearray()
        deadline = time.monotonic() + seconds
        try:
            with selectors.DefaultSelector() as streams:
                streams.register(proc.stdout, selectors.EVENT_READ, stdout)
                streams.register(proc.stderr, selectors.EVENT_READ, stderr)
                while streams.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        refuse('bounded Poppler operation timeout')
                    for key, _ in streams.select(min(remaining, 0.5)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            streams.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        if len(chunk) > cap - len(key.data):
                            refuse('bounded Poppler output exceeded')
                        key.data.extend(chunk)
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            if code != 0:
                refuse('Poppler operation failed')
            return bytes(stdout), bytes(stderr)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
            raise
        finally:
            for stream in (proc.stdout, proc.stderr):
                if stream and not stream.closed:
                    stream.close()
    def run(command, output=None):
        stdout, _ = execute(command, 30, MAX_TEXT)
        if output:
            output.write_bytes(stdout)
            os.chmod(output, 0o600)
        return stdout.decode('utf-8', errors='strict')
    for name, tool in tools.items():
        stdout, stderr = execute([tool, '-v'], 5, 4096)
        tool_versions[name] = {'executable_sha256': sha_file(Path(tool)),
                               'version': (stdout + stderr).decode('utf-8', errors='strict')}
    for label in ('profile', 'autosave'):
        text_by_kind = {}
        for kind in ('source', 'final', 'certificate'):
            name = label + '-' + kind
            pdf = root / (name + '.pdf')
            info = run([tools['pdfinfo'], '-box', str(pdf)], qa / (name + '.info.txt'))
            match = re.search(r'^Pages:\s+(\d+)\s*$', info, re.MULTILINE)
            if not match:
                refuse('actual PDF page count missing')
            pages = int(match.group(1))
            expected_pages = receipt.get('page_count')
            if pages < 1 or pages > 12 or kind != 'certificate' and pages != expected_pages:
                refuse('actual source/final page count differs')
            boxes = run([tools['pdfinfo'], '-f', '1', '-l', str(pages), '-box', str(pdf)], qa / (name + '.boxes.txt'))
            font_text = run([tools['pdffonts'], str(pdf)], qa / (name + '.fonts.txt'))
            fonts = []
            for line in font_text.splitlines()[2:]:
                fields = line.split()
                if not fields:
                    continue
                if len(fields) < 7 or fields[-5] != 'yes':
                    refuse('PDF has an unembedded or unparsable font')
                fonts.append(fields[0])
            if not fonts or kind != 'certificate' and not any('Inter' in name for name in fonts):
                refuse('actual PDF embedded body-font attribution missing')
            text = run([tools['pdftotext'], '-layout', '-enc', 'UTF-8', str(pdf), '-'], qa / (name + '.text.txt'))
            if not text.strip():
                refuse('actual PDF has no extractable text')
            text_by_kind[kind] = compact(text)
            run([tools['pdftoppm'], '-r', '96', '-png', str(pdf), str(qa / name)])
            pngs = sorted(qa.glob(name + '-*.png'))
            if len(pngs) != pages or any(file.stat().st_size == 0 for file in pngs):
                refuse('full-page actual PDF raster inventory incomplete')
            for file in pngs:
                os.chmod(file, 0o600)
            observations[name] = {'pages': pages, 'fonts': fonts, 'page_boxes': boxes,
                                  'text_sha256': hashlib.sha256(text.encode()).hexdigest(),
                                  'rasters': {file.name: sha_file(file) for file in pngs}}
        for party in receipt.get('intended_parties', []):
            name = compact(party['name'])
            if name not in text_by_kind['source'] or name not in text_by_kind['final']:
                refuse('full intended-party identity not visible in source/final PDF text')
        if label == 'autosave' and compact(receipt.get('manual_expected_value', '')) not in text_by_kind['final']:
            refuse('durably saved manual field is absent from final PDF text')
        html = (root / (label + '-certificate-payload.html')).read_text()
        visible = VisibleHTML()
        visible.feed(html)
        if not visible.nodes or any(compact(node) not in text_by_kind['certificate'] for node in visible.nodes):
            refuse('actual certificate PDF omits visible signed HTML content')
        pin_prefix = label + '-final.pdf'
        if expected[pin_prefix] not in text_by_kind['certificate']:
            refuse('full committed final-PDF hash is missing/truncated on certificate')
        # This fixture has unchanged A4 source geometry. Other page formats and
        # rotations remain separate selected native acceptance cases.
        source = observations[label + '-source']['page_boxes']
        final = observations[label + '-final']['page_boxes']
        geometry = lambda value: [line for line in value.splitlines()
                                  if re.match(r'^(Page\s+\d+\s+(size|rot|MediaBox|CropBox|BleedBox|TrimBox|ArtBox)|Page size|Page rot|MediaBox|CropBox|BleedBox|TrimBox|ArtBox):?', line)]
        if not geometry(source) or geometry(source) != geometry(final):
            refuse('actual manual/HTML source-to-final page geometry changed')
    report = {'schema': 1, 'result': 'machine-checks-pass-visual-review-required',
              'scope': 'Offline exact local artifacts only; no legal/provider/production or physical-capacity claim.',
              'tool_versions': tool_versions, 'artifacts': observations,
              'required_next': 'Inspect every full-page PNG and signature/field region against source/geometry; record a separate visual acceptance receipt. Existing font/CDP refusal suite remains required.'}
    (qa / 'pdf-qa-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    os.chmod(qa / 'pdf-qa-receipt.json', 0o600)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('owned PDF QA refused; inspect only private bounded artifacts')
