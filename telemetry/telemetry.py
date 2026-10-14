"""Bounded saved sensor import and passive local dashboard; standard library only."""
import argparse
import csv
import hashlib
import html
import io
import json
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 20000


def read_bytes(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Input exceeds 8 MiB')
    return data


def sensors(path, encoding='utf-8-sig', delimiter=','):
    """Keep columns by position; never infer timezone, device identity or units."""
    raw = read_bytes(path)
    rows = csv.reader(io.StringIO(raw.decode(encoding)), delimiter=delimiter, strict=True)
    headers = next(rows, [])
    if not headers or len(headers) > 2048:
        raise ValueError('Missing header or more than 2048 columns')
    dates = [i for i, h in enumerate(headers) if h.strip().lower() == 'date']
    times = [i for i, h in enumerate(headers) if h.strip().lower() == 'time']
    if len(dates) != 1 or len(times) != 1:
        raise ValueError('Exactly one Date and Time column required')
    samples, gaps, seen = [], [], set()
    for number, row in enumerate(rows, 2):
        if number > MAX_ROWS + 1:
            gaps.append({'row': number, 'reason': 'row-cap'}); break
        if not row or all(not cell.strip() for cell in row):
            continue
        if row == headers:
            gaps.append({'row': number, 'reason': 'repeated-header'}); continue
        if len(row) != len(headers):
            gaps.append({'row': number, 'reason': 'width-mismatch-or-footer'}); continue
        stamp = (row[dates[0]], row[times[0]])
        if not all(part.strip() for part in stamp):
            gaps.append({'row': number, 'reason': 'missing-clock-or-footer'}); continue
        if stamp in seen:
            gaps.append({'row': number, 'reason': 'duplicate-local-clock'})
        seen.add(stamp)
        samples.append({'row': number, 'localClock': list(stamp), 'values': row})
    if len(samples) < 2:
        gaps.append({'row': None, 'reason': 'fewer-than-two-samples'})
    return {'schema': 'sensor-table-v1', 'sourceSHA256': hashlib.sha256(raw).hexdigest(),
            'encoding': encoding, 'delimiter': delimiter, 'timezone': None,
            'clockInterpretation': 'unparsed local strings; UTC ordering unknown',
            'columns': [{'index': i, 'label': h} for i, h in enumerate(headers)],
            'samples': samples, 'gaps': gaps, 'status': 'partial' if gaps else 'parsed',
            'limits': 'String values only; no numeric, health, device identity or stability inference'}


def dashboard(sensor=None, hardware=None):
    sections = []
    for title, value, schema in [('Saved sensor samples', sensor, 'sensor-table-v1'),
                                 ('Saved hardware inventory', hardware, 'hardware-inventory-v1')]:
        if value is not None:
            if not isinstance(value, dict) or value.get('schema') != schema:
                raise ValueError('Unsupported dashboard input schema')
            sections.append('<section><h2>' + title + '</h2><pre>' +
                            html.escape(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre></section>')
    if not sections:
        raise ValueError('Supply at least one saved input')
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local hardware and sensor evidence</title>
<style>body{font:16px system-ui;background:#101923;color:#e6edf4;max-width:1100px;margin:32px auto;padding:20px}section{background:#192938;padding:20px;margin:20px 0;border-radius:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}h1{color:#7cdbca}</style>
<h1>Local hardware and sensor evidence</h1>
<p>Saved observations only. Refreshing this file collects nothing. Missing coverage remains unknown; readings do not establish stability or crash causes.</p>
''' + ''.join(sections) + '</html>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    sensor = commands.add_parser('sensors')
    sensor.add_argument('input')
    sensor.add_argument('--encoding', choices=['utf-8-sig', 'utf-16', 'cp1252'], default='utf-8-sig')
    sensor.add_argument('--delimiter', choices=[',', ';', '\t'], default=',')
    view = commands.add_parser('dashboard')
    view.add_argument('--sensors')
    view.add_argument('--hardware')
    for command in (sensor, view):
        command.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'sensors':
            result = sensors(args.input, args.encoding, args.delimiter)
            output = json.dumps(result, ensure_ascii=False, indent=2)
            code = 2 if result['gaps'] else 0
        else:
            load = lambda path: json.loads(read_bytes(path).decode('utf-8-sig')) if path else None
            output = dashboard(load(args.sensors), load(args.hardware))
            code = 0
        with open(args.output, 'x', encoding='utf-8') as stream:
            stream.write(output)
        return code
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
