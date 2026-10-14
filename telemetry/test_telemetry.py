import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import telemetry as t


class TelemetryTests(unittest.TestCase):
    def parse(self, text, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'sample.csv'
            source.write_bytes(text if isinstance(text, bytes) else text.encode())
            return t.sensors(source, **kwargs)

    def test_duplicate_columns_retained(self):
        result = self.parse('Date,Time,T,T\na,b,1,2\nc,d,3,4\n')
        self.assertEqual([c['index'] for c in result['columns']], [0, 1, 2, 3])
        self.assertEqual(result['samples'][0]['values'][-2:], ['1', '2'])
        self.assertIsNone(result['timezone'])

    def test_bad_width_and_footer_explicit(self):
        result = self.parse('Date,Time,T\na,b,1\nfooter\n,,label\n')
        self.assertEqual(len(result['samples']), 1)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['gaps']), 3)

    def test_repeated_header_and_clock(self):
        result = self.parse('Date,Time,T\na,b,1\nDate,Time,T\na,b,2\n')
        self.assertEqual([g['reason'] for g in result['gaps']],
                         ['repeated-header', 'duplicate-local-clock'])

    def test_missing_or_ambiguous_clock_rejected(self):
        for text in ['', 'Time,T\na,1', 'Date,Date,Time\na,b,c']:
            with self.assertRaises(ValueError): self.parse(text)

    def test_explicit_cp1252(self):
        source = 'Date;Time;Temperature [°C]\na;b;1\nc;d;2'.encode('cp1252')
        with self.assertRaises(UnicodeError): self.parse(source)
        self.assertEqual(self.parse(source, encoding='cp1252', delimiter=';')['status'], 'parsed')

    def test_bounds(self):
        with patch.object(t, 'MAX_BYTES', 4):
            with self.assertRaises(ValueError): self.parse('Date,Time,T')
        with patch.object(t, 'MAX_ROWS', 2):
            result = self.parse('Date,Time,T\na,b,1\nc,d,2\ne,f,3')
            self.assertEqual(len(result['samples']), 2)
            self.assertEqual(result['gaps'][-1]['reason'], 'row-cap')

    def test_html_escapes_untrusted_text(self):
        rendered = t.dashboard(hardware={'schema':'hardware-inventory-v1', 'value':'</pre><script>alert(1)</script>'})
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)
        self.assertIn("default-src 'none'", rendered)

    def test_dashboard_schema_rejected(self):
        for data in [[], {}, {'schema':'unknown'}]:
            with self.assertRaises(ValueError): t.dashboard(sensor=data)
        with self.assertRaises(ValueError): t.dashboard()

    def test_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing.json'
            output.write_text('keep')
            run = subprocess.run([sys.executable, str(Path(t.__file__)), 'sensors',
                                  str(Path(t.__file__).parent/'examples/sensors.synthetic.csv'),
                                  '--output', str(output)], capture_output=True)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(output.read_text(), 'keep')

    def test_cli_synthetic_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(t.__file__).parent
            output = Path(directory) / 'sensors.json'
            run = subprocess.run([sys.executable, str(root/'telemetry.py'), 'sensors',
                                  str(root/'examples/sensors.synthetic.csv'), '--output', str(output)], capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(len(json.loads(output.read_text())['samples']), 2)
            view = Path(directory) / 'dashboard.html'
            run = subprocess.run([sys.executable, str(root/'telemetry.py'), 'dashboard',
                                  '--sensors', str(output), '--hardware', str(root/'examples/hardware.synthetic.json'),
                                  '--output', str(view)], capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('Synthetic CPU', view.read_text())


if __name__ == '__main__': unittest.main()
