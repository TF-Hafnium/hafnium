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
      },
};
