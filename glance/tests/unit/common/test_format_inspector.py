# Copyright 2020 Red Hat, Inc
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import io
import os
import re
import subprocess
import tempfile
from unittest import mock

from oslo_utils import units

from glance.common import format_inspector
from glance.tests import utils as test_utils


def get_size_from_qemu_img(filename):
    output = subprocess.check_output('qemu-img info "%s"' % filename,
                                     shell=True)
    for line in output.split(b'\n'):
        m = re.search(b'^virtual size: .* .([0-9]+) bytes', line.strip())
        if m:
            return int(m.group(1))

    raise Exception('Could not find virtual size with qemu-img')


class TestFormatInspectors(test_utils.BaseTestCase):
    def setUp(self):
        super(TestFormatInspectors, self).setUp()
        self._created_files = []

    def tearDown(self):
        super(TestFormatInspectors, self).tearDown()
        for fn in self._created_files:
            try:
                os.remove(fn)
            except Exception:
                pass

    def _create_img(self, fmt, size, subformat=None, options=None,
                    backing_file=None):
        if fmt == 'vhd':
            # QEMU calls the vhd format vpc
            fmt = 'vpc'

        if options is None:
            options = {}
        opt = ''
        prefix = 'glance-unittest-formatinspector-'

        if subformat:
            options['subformat'] = subformat
            prefix += subformat + '-'

        if options:
            opt += '-o ' + ','.join('%s=%s' % (k, v)
                                    for k, v in options.items())

        if backing_file is not None:
            opt += ' -b %s -F raw' % backing_file

        fn = tempfile.mktemp(prefix=prefix,
                             suffix='.%s' % fmt)
        self._created_files.append(fn)
        subprocess.check_output(
            'qemu-img create -f %s %s %s %i' % (fmt, opt, fn, size),
            shell=True)
        return fn

    def _test_format_at_block_size(self, format_name, img, block_size):
        fmt = format_inspector.get_inspector(format_name)()
        self.assertIsNotNone(fmt,
                             'Did not get format inspector for %s' % (
                                 format_name))
        wrapper = format_inspector.InfoWrapper(open(img, 'rb'), fmt)

        while True:
            chunk = wrapper.read(block_size)
            if not chunk:
                break

        wrapper.close()
        return fmt

    def _test_format_at_image_size(self, format_name, image_size):
        img = self._create_img(format_name, image_size)

        # Some formats have internal alignment restrictions making this not
        # always exactly like image_size, so get the real value for comparison
        virtual_size = get_size_from_qemu_img(img)

        # Read the format in various sizes, some of which will read whole
        # sections in a single read, others will be completely unaligned, etc.
        for block_size in (64 * units.Ki, 512, 17, 1 * units.Mi):
            fmt = self._test_format_at_block_size(format_name, img, block_size)
            self.assertTrue(fmt.format_match,
                            'Failed to match %s at size %i block %i' % (
                                format_name, image_size, block_size))
            self.assertEqual(virtual_size, fmt.virtual_size,
                             ('Failed to calculate size for %s at size %i '
                              'block %i') % (format_name, image_size,
                                             block_size))
            memory = sum(fmt.context_info.values())
            self.assertLess(memory, 512 * units.Ki,
                            'Format used more than 512KiB of memory: %s' % (
                                fmt.context_info))

    def _test_format(self, format_name):
        # Try a few different image sizes, including some odd and very small
        # sizes
        for image_size in (512, 513, 2057, 7):
            self._test_format_at_image_size(format_name, image_size * units.Mi)

    def test_qcow2(self):
        self._test_format('qcow2')

    def test_vhd(self):
        self._test_format('vhd')

    def test_vhdx(self):
        self._test_format('vhdx')

    def test_vmdk(self):
        self._test_format('vmdk')

    def test_from_file_reads_minimum(self):
        img = self._create_img('qcow2', 10 * units.Mi)
        file_size = os.stat(img).st_size
        fmt = format_inspector.QcowInspector.from_file(img)
        # We know everything we need from the first 512 bytes of a QCOW image,
        # so make sure that we did not read the whole thing when we inspect
        # a local file.
        self.assertLess(fmt.actual_size, file_size)

    def test_qcow2_safety_checks(self):
        # Create backing and data-file names (and initialize the backing file)
        backing_fn = tempfile.mktemp(prefix='backing')
        self._created_files.append(backing_fn)
        with open(backing_fn, 'w') as f:
            f.write('foobar')
        data_fn = tempfile.mktemp(prefix='data')
        self._created_files.append(data_fn)

        # A qcow with no backing or data file is safe
        fn = self._create_img('qcow2', 5 * units.Mi, None)
        inspector = format_inspector.QcowInspector.from_file(fn)
        self.assertTrue(inspector.safety_check())

        # A backing file makes it unsafe
        fn = self._create_img('qcow2', 5 * units.Mi, None,
                              backing_file=backing_fn)
        inspector = format_inspector.QcowInspector.from_file(fn)
        self.assertFalse(inspector.safety_check())

        # A data-file makes it unsafe
        fn = self._create_img('qcow2', 5 * units.Mi,
                              options={'data_file': data_fn,
                                       'data_file_raw': 'on'})
        inspector = format_inspector.QcowInspector.from_file(fn)
        self.assertFalse(inspector.safety_check())

        # Trying to load a non-QCOW file is an error
        self.assertRaises(format_inspector.ImageFormatError,
                          format_inspector.QcowInspector.from_file,
                          backing_fn)

    def test_qcow2_feature_flag_checks(self):
        data = bytearray(512)
        data[0:4] = b'QFI\xFB'
        inspector = format_inspector.QcowInspector()
        inspector.region('header').data = data

        # All zeros, no feature flags - all good
        self.assertFalse(inspector.has_unknown_features)

        # A feature flag set in the first byte (highest-order) is not
        # something we know about, so fail.
        data[0x48] = 0x01
        self.assertTrue(inspector.has_unknown_features)

        # The first bit in the last byte (lowest-order) is known (the dirty
        # bit) so that should pass
        data[0x48] = 0x00
        data[0x4F] = 0x01
        self.assertFalse(inspector.has_unknown_features)

        # Currently (as of 2024), the high-order feature flag bit in the low-
        # order byte is not assigned, so make sure we reject it.
        data[0x4F] = 0x80
        self.assertTrue(inspector.has_unknown_features)

    def test_vmdk_safety_checks(self):
        region = format_inspector.CaptureRegion(0, 0)
        inspector = format_inspector.VMDKInspector()
        inspector.new_region('descriptor', region)

        # This should be a legit VMDK descriptor which comments, blank lines,
        # an extent, some ddb content, and some header values.
        legit_desc = ['# This is a comment',
                      '',
                      ' ',
                      'createType=monolithicSparse',
                      'RW 1234 SPARSE "foo.vmdk"',
                      'ddb.adapterType = "MFM',
                      '# EOF']
        region.data = ('\n'.join(legit_desc)).encode('ascii')
        region.length = len(region.data)
        self.assertTrue(inspector.safety_check())

        # Any of these lines should trigger an error indicating that there is
        # something in the descriptor we don't understand
        bad_lines = [
            '#\U0001F4A9',
            'header Name=foo',
            'foo bar',
            'WR 123 SPARSE "foo.vmdk"',
        ]

        for bad_line in bad_lines:
            # Encode as UTF-8 purely so we can test that anything non-ASCII
            # will trigger the decode check
            region.data = bad_line.encode('utf-8')
            region.length = len(region.data)
            self.assertRaisesRegex(format_inspector.ImageFormatError,
                                   'Invalid VMDK descriptor',
                                   inspector.safety_check)

        # Extents with slashes in the name fail the safety check
        region.data = b'RW 123 SPARSE "/etc/shadow"'
        region.length = len(region.data)
        self.assertFalse(inspector.safety_check())

        # A descriptor that specifies no extents fails the safety check
        region.data = b'# Nothing'
        region.length = len(region.data)
        self.assertFalse(inspector.safety_check())

    def test_vmdk_reject_footer(self):
        data = struct.pack('<4sIIQQQQIQQ', b'KDMV', 3, 0, 0, 0, 0, 1, 0, 0,
                           format_inspector.VMDKInspector.GD_AT_END)
        inspector = format_inspector.VMDKInspector()
        inspector.region('header').data = data
        inspector.region('header').length = len(data)
        self.assertRaisesRegex(format_inspector.ImageFormatError,
                               'footer',
                               inspector.post_process)

    def test_vdi(self):
        self._test_format('vdi')

    def _test_format_with_invalid_data(self, format_name):
        fmt = format_inspector.get_inspector(format_name)()
        wrapper = format_inspector.InfoWrapper(open(__file__, 'rb'), fmt)
        while True:
            chunk = wrapper.read(32)
            if not chunk:
                break

        wrapper.close()
        self.assertFalse(fmt.format_match)
        self.assertEqual(0, fmt.virtual_size)
        memory = sum(fmt.context_info.values())
        self.assertLess(memory, 512 * units.Ki,
                        'Format used more than 512KiB of memory: %s' % (
                            fmt.context_info))

    def test_qcow2_invalid(self):
        self._test_format_with_invalid_data('qcow2')

    def test_vhd_invalid(self):
        self._test_format_with_invalid_data('vhd')

    def test_vhdx_invalid(self):
        self._test_format_with_invalid_data('vhdx')

    def test_vmdk_invalid(self):
        self._test_format_with_invalid_data('vmdk')

    def test_vdi_invalid(self):
        self._test_format_with_invalid_data('vdi')


class TestFormatInspectorInfra(test_utils.BaseTestCase):
    def _test_capture_region_bs(self, bs):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))

        regions = [
            format_inspector.CaptureRegion(3, 9),
            format_inspector.CaptureRegion(0, 256),
            format_inspector.CaptureRegion(32, 8),
        ]

        for region in regions:
            # None of them should be complete yet
            self.assertFalse(region.complete)

        pos = 0
        for i in range(0, len(data), bs):
            chunk = data[i:i + bs]
            pos += len(chunk)
            for region in regions:
                region.capture(chunk, pos)

        self.assertEqual(data[3:12], regions[0].data)
        self.assertEqual(data[0:256], regions[1].data)
        self.assertEqual(data[32:40], regions[2].data)

        # The small regions should be complete
        self.assertTrue(regions[0].complete)
        self.assertTrue(regions[2].complete)

        # This region extended past the available data, so not complete
        self.assertFalse(regions[1].complete)

    def test_capture_region(self):
        for block_size in (1, 3, 7, 13, 32, 64):
            self._test_capture_region_bs(block_size)

    def _get_wrapper(self, data):
        source = io.BytesIO(data)
        fake_fmt = mock.create_autospec(format_inspector.get_inspector('raw'))
        return format_inspector.InfoWrapper(source, fake_fmt)

    def test_info_wrapper_file_like(self):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))
        wrapper = self._get_wrapper(data)

        read_data = b''
        while True:
            chunk = wrapper.read(8)
            if not chunk:
                break
            read_data += chunk

        self.assertEqual(data, read_data)

    def test_info_wrapper_iter_like(self):
        data = b''.join(chr(x).encode() for x in range(ord('A'), ord('z')))
        wrapper = self._get_wrapper(data)

        read_data = b''
        for chunk in wrapper:
            read_data += chunk

        self.assertEqual(data, read_data)

    def test_info_wrapper_file_like_eats_error(self):
        wrapper = self._get_wrapper(b'123456')
        wrapper._format.eat_chunk.side_effect = Exception('fail')

        data = b''
        while True:
            chunk = wrapper.read(3)
            if not chunk:
                break
            data += chunk

        # Make sure we got all the data despite the error
        self.assertEqual(b'123456', data)

        # Make sure we only called this once and never again after
        # the error was raised
        wrapper._format.eat_chunk.assert_called_once_with(b'123')

    def test_info_wrapper_iter_like_eats_error(self):
        fake_fmt = mock.create_autospec(format_inspector.get_inspector('raw'))
        wrapper = format_inspector.InfoWrapper(iter([b'123', b'456']),
                                               fake_fmt)
        fake_fmt.eat_chunk.side_effect = Exception('fail')

        data = b''
        for chunk in wrapper:
            data += chunk

        # Make sure we got all the data despite the error
        self.assertEqual(b'123456', data)

        # Make sure we only called this once and never again after
        # the error was raised
        fake_fmt.eat_chunk.assert_called_once_with(b'123')

    def test_get_inspector(self):
        self.assertEqual(format_inspector.QcowInspector,
                         format_inspector.get_inspector('qcow2'))
        self.assertIsNone(format_inspector.get_inspector('foo'))
