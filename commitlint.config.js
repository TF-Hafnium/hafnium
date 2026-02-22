/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-empty': [2, 'never'],
    'scope-enum': [
      2,
      'always',
      [
        // FF-A
        'ff-a',
        'vm',
        'cpus',
        'mm',           // memory-management
        'ipi',
        'gicv3',
        'manifest',

        // Memory sharing & notifications
        'mem_share',
        'notifications',
        'interrupts',
        'iommu',
        'smmuv3',

        // Partition lifecycle
        'lifecycle',

        // Test framework
        'hftest',
        'static-checks',

        // Build and tooling
        'shrinkwrap',
        'docker',
        'commitlint',
        'git',

        // submodules
        'reference',
        'dtc',
        'gtest',

        // Fallback scope for any miscellaneous change
        'misc'
      ],
    ],
  },
};
